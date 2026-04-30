import logging
import re
import time
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.helpers.upgrade_helpers import install_sonic, reboot, check_sonic_version

logger = logging.getLogger(__name__)


def boot_into_base_image(duthost, localhost, base_image, tbinfo):
    target_version = _install_base_image(duthost, base_image, tbinfo)
    # Perform a cold reboot
    logger.info("Cold reboot the DUT to make the base image as current")
    # for 6100 devices, sometimes cold downgrade will not work, use soft-reboot here
    reboot_type = 'soft' if "s6100" in duthost.facts["platform"] else 'cold'
    reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
    check_sonic_version(duthost, target_version)


def boot_into_base_image_t2(duthosts, localhost, base_image, tbinfo):
    target_vers = {}
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts:
            future = executor.submit(_install_base_image, duthost, base_image, tbinfo)
            target_vers[duthost] = future.get()  # Should all be the same, but following best practice

    # Rebooting the supervisor host will reboot all T2 DUTs
    suphost = duthosts.supervisor_nodes[0]
    reboot(suphost, localhost, reboot_type='cold', safe_reboot=True)

    for duthost in duthosts:
        check_sonic_version(duthost, target_vers[duthost])


def _install_base_image(duthost, base_image, tbinfo):
    logger.info("Installing {}".format(base_image))
    try:
        target_version = install_sonic(duthost, base_image, tbinfo)
    except RunAnsibleModuleFail as err:
        migration_err_regexp = r"Traceback.*migrate_sonic_packages.*SonicRuntimeException"
        msg = err.results['msg'].replace('\n', '')
        if re.search(migration_err_regexp, msg):
            logger.info(
                "Ignore the package migration error when downgrading to base_image")
            target_version = duthost.shell(
                "cat /tmp/downloaded-sonic-image-version")['stdout']
        else:
            raise err
    # Remove old config_db before rebooting the DUT in case it is not successfully
    # removed in install_sonic due to migration error
    logger.info("Remove old config_db file if exists, to load minigraph from scratch")
    if duthost.shell("ls /host/old_config/minigraph.xml", module_ignore_errors=True)['rc'] == 0:
        duthost.shell("rm -f /host/old_config/config_db.json")
        duthost.shell("rm -f /host/old_config/golden_config_db.json")

    return target_version


def cleanup_prev_images(duthost):
    logger.info("Cleaning up previously installed images on DUT")
    current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
    duthost.shell("sonic_installer set_next_boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer set-next-boot {}".format(current_os_version), module_ignore_errors=True)
    duthost.shell("sonic_installer cleanup -y", module_ignore_errors=True)


def workaround_ensure_all_portchannels_have_ips(duthost):
    """
    Port of the sonic-metadata postupgrade `fix_portchannel_not_having_ip_address` patch.

    On certain platforms running 202405/202411/202505, after an upgrade some PortChannel
    interfaces can come up without an IPv4 and/or IPv6 address even though the address is
    present in CONFIG_DB. This helper checks the commonly-impacted PortChannels and, if
    either family's "scope global" address is missing from `ip addr show`, fetches the
    expected address from CONFIG_DB and reapplies it via `config interface ip add`.

    NOTE: This has been fixed in the image starting from 202511:
    #   https://github.com/sonic-net/sonic-swss/pull/3984
    """
    affected_platforms = (
        "x86_64-arista_7060_cx32s",
        "x86_64-mlnx_msn2700-r0",
        "x86_64-arista_7050cx3_32s",
    )
    affected_version_prefixes = ("202405", "202411", "202505")

    os_version = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    platform = duthost.facts["platform"]

    if not any(p in os_version for p in affected_version_prefixes):
        logger.info("Running SONiC version {} is not 202405/202411/202505, skipping PortChannel IP check"
                    .format(os_version))
        return
    if platform not in affected_platforms:
        logger.info("Platform {} is not an affected platform, skipping PortChannel IP check"
                    .format(platform))
        return

    logger.info("Checking PortChannel IP addresses (os_version={}, platform={})"
                .format(os_version, platform))

    # PortChannel1 and PortChannel1001 are the commonly-impacted ones.
    # PortChannel2 is the 3rd most common.
    for port_channel in ("PortChannel1", "PortChannel101", "PortChannel1001", "PortChannel2"):
        result = duthost.shell("ip addr show dev {}".format(port_channel),
                               module_ignore_errors=True)
        if result["rc"] != 0:
            logger.warning("Non-zero exit code when trying to get info about {}, "
                           "assuming it doesn't exist".format(port_channel))
            continue
        addr_show = result["stdout"]

        missing_ip = {}
        if not re.search(r'inet (\S+) scope global', addr_show):
            missing_ip['ipv4'] = True
        if not re.search(r'inet6 (\S+) scope global', addr_show):
            missing_ip['ipv6'] = True

        if not missing_ip:
            logger.info("{} has both an IPv4 and IPv6 address, continuing".format(port_channel))
            continue

        logger.warning("{} is missing addresses: {}".format(port_channel, list(missing_ip.keys())))

        # Generate the missing config as needed
        config_lines = []
        if missing_ip.get('ipv4'):
            v4_addr = duthost.shell(
                "sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_INTERFACE|{}|*' | grep -v : | cut -d'|' -f 3"
                .format(port_channel), module_ignore_errors=True)["stdout"].strip()
            if v4_addr:
                config_lines.append("config interface ip add {} {}".format(port_channel, v4_addr))

        if missing_ip.get('ipv6'):
            v6_addr = duthost.shell(
                "sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_INTERFACE|{}|*' | grep : | cut -d'|' -f 3"
                .format(port_channel), module_ignore_errors=True)["stdout"].strip()
            if v6_addr:
                config_lines.append("config interface ip add {} {}".format(port_channel, v6_addr))

        if not config_lines:
            logger.error("Failed to generate config commands for {}".format(port_channel))
            continue

        # Push the config
        for config_line in config_lines:
            logger.info("Running: {}".format(config_line))
            cfg_result = duthost.shell(config_line, module_ignore_errors=True)
            if cfg_result["rc"] != 0:
                logger.warning("Adding portchannel IP via '{}' returned {}: {}"
                               .format(config_line, cfg_result["rc"], cfg_result.get("stderr")))

        time.sleep(3)

        # Post-check for IP assignment on the port-channel
        post_result = duthost.shell("ip addr show dev {}".format(port_channel),
                                    module_ignore_errors=True)["stdout"]
        missing_ip_post = {}
        if not re.search(r'inet (\S+) scope global', post_result):
            missing_ip_post['ipv4'] = True
        if not re.search(r'inet6 (\S+) scope global', post_result):
            missing_ip_post['ipv6'] = True

        if missing_ip_post:
            logger.error("Post-check failed for {}, missing: {}"
                         .format(port_channel, list(missing_ip_post.keys())))
        else:
            logger.info("Post-check passed for {}".format(port_channel))

