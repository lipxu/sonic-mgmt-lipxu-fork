import re
import datetime
import ipaddress
import sys
import random
import pytest
import contextlib
import time
import logging

from tests.ptf_runner import ptf_runner
from tests.common import constants
from tests.common import config_reload
from tests.common.cisco_data import is_cisco_device
from tests.common.devices.eos import EosHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.mellanox_data import is_mellanox_device

# If the version of the Python interpreter is greater or equal to 3, set the unicode variable to the str class.
if sys.version_info[0] >= 3:
    unicode = str

EXPECT_PFC_WD_DETECT_RE = ".* detected PFC storm .*"
VENDOR_SPEC_ADDITIONAL_INFO_RE = {
    "mellanox":
        r"additional info: occupancy:[0-9]+\|packets:[0-9]+\|packets_last:[0-9]+\|pfc_rx_packets:[0-9]+\|"
        r"pfc_rx_packets_last:[0-9]+\|pfc_duration:[0-9]+\|pfc_duration_last:[0-9]+\|timestamp:[0-9]+(?:\.[0-9]+)?\|"
        r"timestamp_last:[0-9]+(?:\.[0-9]+)?\|(?:effective|real)_poll_time:[0-9]+(?:\.[0-9]+)?"
    }

EXPECT_PFC_WD_RESTORE_RE = ".*storm restored.*"
PFCWD_DEFAULT_DETECT_TIME = 200
PFCWD_DEFAULT_RESTORE_TIME = 200
PFCWD_DEFAULT_POLL_INTERVAL = 200
PFCWD_DEFAULT_PORT_NUM = 32
PFCWD_MAX_POLL_INTERVAL = 1000

# Documentation-only address space (RFC 5737 and RFC 3849) used to give every PortChannel
# member its own routed neighbor address during the all-port storm test. These prefixes are
# reserved for documentation and are not used anywhere else in this repository, so they
# cannot collide with real testbed addressing. Note that 2001:db8:1::/64 must be avoided:
# it is the PTF management subnet (see ansible/testbed.yaml).
PFCWD_MEMBER_SUBNET_IPV4 = "192.0.2.0/24"
PFCWD_MEMBER_SUBNET_IPV6 = "2001:db8:fc00::/64"

logger = logging.getLogger(__name__)


class TrafficPorts(object):
    """ Generate a list of ports needed for the PFC Watchdog test"""
    def __init__(self, mg_facts, neighbors, vlan_nw, topo, config_facts, ip_version):
        """
        Args:
            mg_facts (dict): parsed minigraph info
            neighbors (list):  'device_conn' info from connection graph facts
            vlan_nw (string): ip in the vlan range specified in the DUT

        """
        self.mg_facts = mg_facts
        self.bgp_info = self.mg_facts['minigraph_bgp']
        self.port_idx_info = self.mg_facts['minigraph_ptf_indices']
        self.pc_info = self.mg_facts['minigraph_portchannels']
        self.vlan_info = self.mg_facts['minigraph_vlans']
        self.neighbors = neighbors
        self.vlan_nw = vlan_nw
        self.test_ports = dict()
        self.pfc_wd_rx_port = None
        self.pfc_wd_rx_port_addr = None
        self.pfc_wd_rx_neighbor_addr = None
        self.pfc_wd_rx_port_id = None
        self.topo = topo
        self.config_facts = config_facts
        self.ip_version = ip_version

    def build_port_list(self):
        """
        Generate a list of ports to be used for the test

        For T0 topology, the port list is built parsing the portchannel and vlan info and for T1,
        port list is constructed from the interface info
        """
        if self.mg_facts['minigraph_interfaces']:
            self.parse_intf_list()
        elif self.mg_facts['minigraph_portchannels']:
            self.parse_pc_list()
        elif 'minigraph_vlan_sub_interfaces' in self.mg_facts:
            self.parse_vlan_sub_interface_list()
        if self.mg_facts['minigraph_vlans']:
            self.test_ports.update(self.parse_vlan_list())
        return self.test_ports

    def parse_intf_list(self):
        """
        Built the port info from the ports in 'minigraph_interfaces'

        The constructed port info is a dict with a port as the key (transmit port) and value contains
        all the info associated with this port (its fanout neighbor, receive port, receive ptf id,
        transmit ptf id, neighbor addr etc).  The first port in the list is assumed to be the Rx port.
        The rest of the ports will use this port as the Rx port while populating their dict
        info. The selected Rx port when used as a transmit port will use the next port in
        the list as its associated Rx port
        """
        pfc_wd_test_port = None
        first_pair = False
        for intf in self.mg_facts['minigraph_interfaces']:
            if ipaddress.ip_address(str(intf['addr'])).version != self.ip_version:
                continue
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_port = intf['attachto']
                self.pfc_wd_rx_port_addr = intf['addr']
                self.pfc_wd_rx_port_id = self.port_idx_info[self.pfc_wd_rx_port]
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = intf['attachto']
                pfc_wd_test_port_addr = intf['addr']
                pfc_wd_test_port_id = self.port_idx_info[pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for item in self.bgp_info:
                    if ipaddress.ip_address(str(item['addr'])).version != self.ip_version:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and\
                            str(item['peer_addr']).lower() == str(self.pfc_wd_rx_port_addr).lower():
                        self.pfc_wd_rx_neighbor_addr = item['addr']
                    if str(item['peer_addr']).lower() == str(pfc_wd_test_port_addr).lower():
                        pfc_wd_test_neighbor_addr = item['addr']

                self.test_ports[pfc_wd_test_port] = {
                    'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'rx_port': [self.pfc_wd_rx_port],
                    'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'peer_device': self.neighbors.get(pfc_wd_test_port, {}).get('peerdevice', ''),
                    'test_port_id': pfc_wd_test_port_id,
                    'rx_port_id': [self.pfc_wd_rx_port_id],
                    'test_port_type': 'interface'
                    }
            # populate info for the first port
            if first_pair:
                self.test_ports[self.pfc_wd_rx_port] = {
                    'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'rx_port': [pfc_wd_test_port],
                    'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'peer_device': self.neighbors.get(self.pfc_wd_rx_port, {}).get('peerdevice', ''),
                    'test_port_id': self.pfc_wd_rx_port_id,
                    'rx_port_id': [pfc_wd_test_port_id],
                    'test_port_type': 'interface'
                    }

            first_pair = False

    def parse_pc_list(self):
        """
        Built the port info from the ports in portchannel

        The constructed port info is a dict with a port as the key (transmit port) and value contains
        all the info associated with this port (its fanout neighbor, receive ports, receive
        ptf ids, transmit ptf ids, neighbor portchannel addr, its own portchannel addr etc).
        The first port in the list is assumed to be the Rx port. The rest
        of the ports will use this port as the Rx port while populating their dict
        info. The selected Rx port when used as a transmit port will use the next port in
        the list as its associated Rx port
        """
        pfc_wd_test_port = None
        first_pair = False
        for item in self.mg_facts['minigraph_portchannel_interfaces']:
            if ipaddress.ip_address(str(item['addr'])).version != self.ip_version:
                continue
            pc = item['attachto']
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_portchannel = pc
                self.pfc_wd_rx_port = self.pc_info[pc]['members']
                self.pfc_wd_rx_port_addr = item['addr']
                self.pfc_wd_rx_port_id = [self.port_idx_info[port] for port in self.pfc_wd_rx_port]
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = self.pc_info[pc]['members']
                pfc_wd_test_port_addr = item['addr']
                pfc_wd_test_port_id = [self.port_idx_info[port] for port in pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for bgp_item in self.bgp_info:
                    if ipaddress.ip_address(str(bgp_item['addr'])).version != self.ip_version:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and\
                            str(bgp_item['peer_addr']).lower() == str(self.pfc_wd_rx_port_addr).lower():
                        self.pfc_wd_rx_neighbor_addr = bgp_item['addr']
                    if str(bgp_item['peer_addr']).lower() == str(pfc_wd_test_port_addr).lower():
                        pfc_wd_test_neighbor_addr = bgp_item['addr']

                for port in pfc_wd_test_port:
                    self.test_ports[port] = {'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                                             'rx_port': self.pfc_wd_rx_port,
                                             'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                             'peer_device': self.neighbors.get(port, {}).get('peerdevice', ''),
                                             'test_port_id': self.port_idx_info[port],
                                             'rx_port_id': self.pfc_wd_rx_port_id,
                                             'test_portchannel_members': pfc_wd_test_port_id,
                                             'test_port_type': 'portchannel'
                                             }
            # populate info for the first port
            if first_pair:
                for port in self.pfc_wd_rx_port:
                    self.test_ports[port] = {'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                             'rx_port': pfc_wd_test_port,
                                             'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                                             'peer_device': self.neighbors.get(port, {}).get('peerdevice', ''),
                                             'test_port_id': self.port_idx_info[port],
                                             'rx_port_id': pfc_wd_test_port_id,
                                             'test_portchannel_members': self.pfc_wd_rx_port_id,
                                             'test_port_type': 'portchannel'
                                             }

            first_pair = False

    def parse_vlan_list(self):
        """
        Add vlan specific port info to the already populated port info dict.

        Each vlan interface will be the key and value contains all the info associated with this port
        (receive fanout neighbor, receive port receive ptf id, transmit ptf id, neighbor addr etc).

        Args:
            None

        Returns:
            temp_ports (dict): port info constructed from the vlan interfaces
        """
        temp_ports = dict()
        # In Python2, dict.values() returns list object, but in Python3 returns an iterable but not indexable object.
        # So that convert to list explicitly.
        vlan_details = list(self.vlan_info.values())[0]
        # Filter(remove) PortChannel interfaces from VLAN members list
        vlan_members = [port for port in vlan_details['members'] if 'PortChannel' not in port]

        vlan_type = vlan_details.get('type')
        vlan_id = vlan_details['vlanid']
        rx_port = self.pfc_wd_rx_port if isinstance(self.pfc_wd_rx_port, list) else [self.pfc_wd_rx_port]
        rx_port_id = self.pfc_wd_rx_port_id if isinstance(self.pfc_wd_rx_port_id, list) else [self.pfc_wd_rx_port_id]
        for item in vlan_members:
            ip_addr = self.vlan_nw if 'dualtor' not in self.topo else \
                      self.config_facts['MUX_CABLE'][item][f'server_ipv{self.ip_version}'].split('/')[0]
            temp_ports[item] = {'test_neighbor_addr': ip_addr,
                                'rx_port': rx_port,
                                'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                                'peer_device': self.neighbors.get(item, {}).get('peerdevice', ''),
                                'test_port_id': self.port_idx_info[item],
                                'rx_port_id': rx_port_id,
                                'test_port_type': 'vlan'
                                }
            if hasattr(self, 'pfc_wd_rx_port_vlan_id'):
                temp_ports[item]['rx_port_vlan_id'] = self.pfc_wd_rx_port_vlan_id
            if vlan_type is not None and vlan_type == 'Tagged':
                temp_ports[item]['test_port_vlan_id'] = vlan_id

        return temp_ports

    def parse_vlan_sub_interface_list(self):
        """Build the port info from the vlan sub-interfaces."""
        pfc_wd_test_port = None
        first_pair = False
        for sub_intf in self.mg_facts['minigraph_vlan_sub_interfaces']:
            if ipaddress.ip_address(str(sub_intf['addr'])).version != self.ip_version:
                continue
            intf_name, vlan_id = sub_intf['attachto'].split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
            # first port
            if not self.pfc_wd_rx_port:
                self.pfc_wd_rx_port = intf_name
                self.pfc_wd_rx_port_addr = sub_intf['addr']
                self.pfc_wd_rx_port_id = self.port_idx_info[self.pfc_wd_rx_port]
                self.pfc_wd_rx_port_vlan_id = vlan_id
            elif not pfc_wd_test_port:
                # second port
                first_pair = True

            # populate info for all ports except the first one
            if first_pair or pfc_wd_test_port:
                pfc_wd_test_port = intf_name
                pfc_wd_test_port_addr = sub_intf['addr']
                pfc_wd_test_port_id = self.port_idx_info[pfc_wd_test_port]
                pfc_wd_test_neighbor_addr = None

                for item in self.bgp_info:
                    if ipaddress.ip_address(str(item['addr'])).version != self.ip_version:
                        continue
                    if not self.pfc_wd_rx_neighbor_addr and\
                            str(item['peer_addr']).lower() == str(self.pfc_wd_rx_port_addr).lower():
                        self.pfc_wd_rx_neighbor_addr = item['addr']
                    if str(item['peer_addr']).lower() == str(pfc_wd_test_port_addr).lower():
                        pfc_wd_test_neighbor_addr = item['addr']

                self.test_ports[pfc_wd_test_port] = {
                    'test_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'rx_port': [self.pfc_wd_rx_port],
                    'rx_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'peer_device': self.neighbors.get(pfc_wd_test_port, {}).get('peerdevice', ''),
                    'test_port_id': pfc_wd_test_port_id,
                    'rx_port_id': [self.pfc_wd_rx_port_id],
                    'rx_port_vlan_id': self.pfc_wd_rx_port_vlan_id,
                    'test_port_vlan_id': vlan_id,
                    'test_port_type': 'interface'
                    }
            # populate info for the first port
            if first_pair:
                self.test_ports[self.pfc_wd_rx_port] = {
                    'test_neighbor_addr': self.pfc_wd_rx_neighbor_addr,
                    'rx_port': [pfc_wd_test_port],
                    'rx_neighbor_addr': pfc_wd_test_neighbor_addr,
                    'peer_device': self.neighbors.get(self.pfc_wd_rx_port, {}).get('peerdevice', ''),
                    'test_port_id': self.pfc_wd_rx_port_id,
                    'rx_port_id': [pfc_wd_test_port_id],
                    'rx_port_vlan_id': vlan_id,
                    'test_port_vlan_id': self.pfc_wd_rx_port_vlan_id,
                    'test_port_type': 'interface'
                    }

            first_pair = False


def set_pfc_timers():
    """
    Set PFC timers

    Args:
        None

    Returns:
        pfc_timers (dict)
    """
    pfc_timers = {'pfc_wd_detect_time': 400,
                  'pfc_wd_restore_time': 400,
                  'pfc_wd_restore_time_large': 3000,
                  'pfc_wd_poll_time': 400
                  }
    return pfc_timers


def update_pfc_poll_interval(duthost, poll_interval):
    logger.info("Setting PFC watchdog poll interval to {}ms".format(poll_interval))
    duthost.command("pfcwd interval {}".format(poll_interval))


def calculate_pfcwd_default_timers(duthost):
    """
    Calculate PFC watchdog default timers dynamically based on port count.

    The logic from sonic-utilities pfcwd start_default:
    https://github.com/sonic-net/sonic-utilities/blob/fb3d73db/pfcwd/main.py#L402

    Args:
        duthost: DUT host instance

    Returns:
        pfc_timers (dict): dynamically calculated PFC watchdog timers
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']
    port_num = len(config_facts.get('PORT', {}))

    multiply = max(1, (port_num - 1) // PFCWD_DEFAULT_PORT_NUM + 1)

    poll_interval = min(PFCWD_DEFAULT_POLL_INTERVAL * multiply, PFCWD_MAX_POLL_INTERVAL)

    pfc_timers = {
        'pfc_wd_detect_time': PFCWD_DEFAULT_DETECT_TIME * multiply,
        'pfc_wd_restore_time': PFCWD_DEFAULT_RESTORE_TIME * multiply,
        'pfc_wd_restore_time_large': 3000,
        'pfc_wd_poll_time': poll_interval
    }

    logger.info(f"Port count: {port_num}, multiply factor: {multiply}, calculated PFC timers: {pfc_timers}")

    return pfc_timers


def select_test_ports(test_ports):
    """
    Select a subset of ports from the generated port info

    Args:
        test_ports (dict): Constructed port info

    Returns:
        selected_ports (dict): random port info or set of ports matching seed
    """
    selected_ports = dict()
    rx_ports = set()
    if len(test_ports) > 2:
        modulo = int(len(test_ports)/3)
        seed = int(len(test_ports)/2)
        for port, port_info in test_ports.items():
            rx_port = port_info["rx_port"]
            if isinstance(rx_port, (list, tuple)):
                rx_ports.update(rx_port)
            else:
                rx_ports.add(rx_port)
            if (int(port_info['test_port_id']) % modulo) == (seed % modulo):
                selected_ports[port] = port_info
        # filter out selected ports that also act as rx ports
        selected_ports = {p: pi for p, pi in list(selected_ports.items())
                          if p not in rx_ports}
    # if only 1 or 2 ports avail, take only one, as they are eachother's rx ports
    if not selected_ports:
        random_port = list(test_ports.keys())[0]
        selected_ports[random_port] = test_ports[random_port]

    logger.info("select_test_ports: {}".format(selected_ports.keys()))
    return selected_ports


def start_wd_on_ports(duthost, port, restore_time, detect_time, action="drop"):
    """
    Starts PFCwd on ports

    Args:
        port (string): single port or space separated list of ports
        restore_time (int): PFC storm restoration time
        detect_time (int): PFC storm detection time
        action (string): PFCwd action. values include 'drop', 'forward'
    """
    duthost.command("pfcwd start --action {} --restoration-time {} {} {}"
                    .format(action, restore_time, port, detect_time))


def fetch_vendor_specific_diagnosis_re(duthost):
    """
    Fetch regular expression of vendor specific diagnosis information
    Args:
        duthost: The duthost object
    """
    unsupported_branches = ['202012', '202205', '202211']
    if duthost.os_version in unsupported_branches or duthost.sonic_release in unsupported_branches:
        return ""

    return VENDOR_SPEC_ADDITIONAL_INFO_RE.get(duthost.facts["asic_type"], "")


def is_pfcwd_hw_recovery_enabled(duthost):
    """
    Check if PFC watchdog is using hardware-based recovery mechanism.

    Hardware-based recovery uses ASIC-level PFC DLR which controls egress/TX
    traffic by ignoring PFC XOFF. The per-queue TX OK/DROP cells surfaced by
    'show pfcwd stats' are sourced from the software-recovery code path and
    stay at 0 on HW-recovery platforms even when silicon is dropping.

    Returns:
        bool: True if RECOVERY_MECHANISM is "hardware", False otherwise.
    """
    try:
        cmd = 'sonic-db-cli STATE_DB HGET "PFC_WD_STATE_TABLE|PFC_WD" "RECOVERY_MECHANISM"'
        result = duthost.shell(cmd, module_ignore_errors=True)
        output = result.get('stdout', '').strip().strip('"').strip("'").lower()
        is_hardware = (output == "hardware")
        logger.info("PFC watchdog recovery mechanism: {} (hardware={})".format(
            output or "not set", is_hardware))
        return is_hardware
    except Exception as e:
        logger.error("Exception while checking recovery mechanism: {}".format(str(e)))
        return False


@pytest.fixture(scope='class', autouse=False)
def start_background_traffic(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        pfc_queue_idx,
        setup_pfc_test,
        copy_ptftests_directory,
        ptfhost,
        tbinfo
        ):
    """
       This fixutre starts a background traffic during
       the test. This will start a continuous traffic flow from PTF
       exiting the test port.

       This uses a fixture pfc_queue_idx: which *must* be defined in the
       test script before using this fixture.
    """
    if duthosts[enum_rand_one_per_hwsku_frontend_hostname].facts['asic_type'] != "cisco-8000":
        yield
        return

    # This is needed only for cisco-8000
    program_name = "pfcwd_background_traffic"
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dst_dut_intf = list(setup_pfc_test['test_ports'].keys())[0]
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports = []
    for vlan in mg_facts['minigraph_vlans'].keys():
        vlan_ports.extend(mg_facts['minigraph_vlans'][vlan]['members'])
    all_ip_intfs = mg_facts['minigraph_interfaces'] + mg_facts['minigraph_portchannel_interfaces']
    non_vlan_ports = set(list(setup_pfc_test['test_ports'])) - set(vlan_ports) - set([dst_dut_intf])
    src_dut_intf = random.choice(list(non_vlan_ports))
    dest_mac = dut.get_dut_iface_mac(src_dut_intf)
    # Find out if the selected port is a lag member
    # If so, we need to use the neighbor address of the portchannel.
    # else, we need the neighbor address of the interface itself.
    required_intf = dst_dut_intf
    for intf in mg_facts['minigraph_portchannels']:
        if dst_dut_intf in mg_facts['minigraph_portchannels'][intf]['members']:
            required_intf = intf
            break
    # At this point, required_intf is either a portchannel or Ethernet port.
    # It should have a neighbor address or it is an error.
    dst_ip_addr = None
    for intf_obj in all_ip_intfs:
        if intf_obj['attachto'] == required_intf:
            dst_ip_addr = intf_obj['peer_addr']
            break
    if dst_ip_addr is None:
        raise RuntimeError("Could not find the neighbor address for intf:{}".format(required_intf))
    ptf_src_port = mg_facts['minigraph_ptf_indices'][src_dut_intf]
    ptf_dst_port = mg_facts['minigraph_ptf_indices'][dst_dut_intf]
    extra_vars = {
        f'{program_name}_args':
            'dest_mac=u"{}";dst_ip_addr={};ptf_src_port={};ptf_dst_port={};pfc_queue_idx={}'.format(
                dest_mac,
                dst_ip_addr,
                ptf_src_port,
                ptf_dst_port,
                pfc_queue_idx
                )}
    try:
        ptfhost.command('supervisorctl stop {}'.format(program_name))
    except BaseException:
        pass

    ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
    script_args = \
        '''dest_mac=u"{}";dst_ip_addr="{}";ptf_src_port={};ptf_dst_port={};pfc_queue_idx={}'''.format(
                dest_mac,
                dst_ip_addr,
                ptf_src_port,
                ptf_dst_port,
                pfc_queue_idx)
    supervisor_conf_content = ('''
[program:{program_name}]
command=/root/env-python3/bin/ptf --test-dir /root/ptftests/py3 {program_name}.BG_pkt_sender'''
                               ''' --platform-dir /root/ptftests/ -t'''
                               ''' '{script_args}' --relax  --platform remote
process_name={program_name}
stdout_logfile=/tmp/{program_name}.out.log
stderr_logfile=/tmp/{program_name}.err.log
redirect_stderr=false
autostart=false
autorestart=true
startsecs=1
numprocs=1
'''.format(script_args=script_args, program_name=program_name))
    ptfhost.copy(
        content=supervisor_conf_content,
        dest=f'/etc/supervisor/conf.d/{program_name}.conf')

    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')
    ptfhost.command(f'supervisorctl start {program_name}')

    yield

    try:
        ptfhost.command(f'supervisorctl stop {program_name}')
    except BaseException:
        pass
    ptfhost.command(f'supervisorctl remove {program_name}')


@contextlib.contextmanager
def send_background_traffic(duthost, ptfhost, storm_hndle, selected_test_ports, test_ports_info, pkt_count=100000):
    """Send background traffic, stop the background traffic when the context finish """
    if is_mellanox_device(duthost) or is_cisco_device(duthost):
        background_traffic_params = _prepare_background_traffic_params(duthost, storm_hndle,
                                                                       selected_test_ports,
                                                                       test_ports_info,
                                                                       pkt_count)
        background_traffic_log = _send_background_traffic(ptfhost, background_traffic_params)
        # Ensure the background traffic is running before moving on
        time.sleep(1)
    yield
    if is_mellanox_device(duthost) or is_cisco_device(duthost):
        _stop_background_traffic(ptfhost, background_traffic_log)


def _prepare_background_traffic_params(duthost, queues, selected_test_ports, test_ports_info, pkt_count):
    src_ports = []
    dst_ports = []
    src_ips = []
    dst_ips = []
    for selected_test_port in selected_test_ports:
        selected_test_port_info = test_ports_info[selected_test_port]
        if isinstance(selected_test_port_info["rx_port_id"], list):
            src_ports.append(selected_test_port_info["rx_port_id"][0])
        else:
            src_ports.append(selected_test_port_info["rx_port_id"])
        dst_ports.append(selected_test_port_info["test_port_id"])
        dst_ips.append(selected_test_port_info["test_neighbor_addr"])
        src_ips.append(selected_test_port_info["rx_neighbor_addr"])

    # The DUT picks the egress port by looking up the destination address, so ports that
    # share one address cannot each get their own flow: the traffic ends up on whichever
    # port owns the neighbor entry or wins the LAG hash. Report it instead of silently
    # covering fewer ports than the caller asked for.
    duplicate_addrs = {addr for addr in dst_ips if dst_ips.count(addr) > 1}
    if duplicate_addrs:
        logger.warning("Background traffic covers %d of %d ports: %s are shared by several ports",
                       len(set(dst_ips)), len(dst_ips), sorted(duplicate_addrs))

    router_mac = duthost.get_dut_iface_mac(selected_test_ports[0])

    ptf_params = {'router_mac': router_mac,
                  'src_ports': src_ports,
                  'dst_ports': dst_ports,
                  'src_ips': src_ips,
                  'dst_ips': dst_ips,
                  'queues': queues,
                  'bidirection': False,
                  'pkt_count': pkt_count}

    return ptf_params


def _send_background_traffic(ptfhost, ptf_params):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/pfc_wd_background_traffic.PfcWdBackgroundTrafficTest.{}.log".format(timestamp)
    ptf_runner(ptfhost, "ptftests", "pfc_wd_background_traffic.PfcWdBackgroundTrafficTest", "/root/ptftests",
               params=ptf_params, log_file=log_file, is_python3=True, async_mode=True)

    return log_file


def _stop_background_traffic(ptfhost, background_traffic_log):
    pids = ptfhost.shell(f"pgrep -f {background_traffic_log}")["stdout_lines"]
    for pid in pids:
        ptfhost.shell(f"kill -9 {pid}", module_ignore_errors=True)


def has_neighbor_device(setup_pfc_test):
    """
    Check if there are neighbor devices present

    Args:
        setup_pfc_test (fixture): Module scoped autouse fixture for PFCwd

    Returns:
        bool: True if there are neighbor devices present, False otherwise
    """
    for _, details in setup_pfc_test['selected_test_ports'].items():
        # 'rx_port' and 'rx_port_id' are expected to be conjugate attributes
        # if one is unset or contains None, the other should be as well
        if (not details.get('rx_port') or None in details['rx_port']) or \
                (not details.get('rx_port_id') or None in details['rx_port_id']):
            return False  # neighbor devices are not present
    return True


def check_pfc_storm_state(dut, port, queue):
    """
    Helper function to check if PFC storm is detected/restored on a given queue
    """
    pfcwd_stats = dut.show_and_parse("show pfcwd stats")
    queue_name = str(port) + ":" + str(queue)
    for entry in pfcwd_stats:
        if entry["queue"] == queue_name:
            logger.info("PFCWD status on queue {} stats: {}".format(queue_name, entry))
            return entry['storm detected/restored']
    logger.info("PFCWD not triggered on queue {}".format(queue_name))
    return None


def verify_pfc_storm_in_expected_state(dut, port, queue, expected_state):
    """
    Helper function to verify if PFC storm on a specific queue is in expected state
    """
    pfcwd_stat = parser_show_pfcwd_stat(dut, port, queue)
    if dut.facts['asic_type'] == 'vs':
        return True
    if not pfcwd_stat:
        logger.info(f'Port {port} Storm verification : no watchdog stats')
        return False
    if expected_state == "storm":
        if ("storm" in pfcwd_stat[0]['status']) and \
                int(pfcwd_stat[0]['storm_detect_count']) > int(pfcwd_stat[0]['restored_count']):
            return True
    else:
        if ("storm" not in pfcwd_stat[0]['status']) and \
                int(pfcwd_stat[0]['storm_detect_count']) == int(pfcwd_stat[0]['restored_count']):
            return True
    return False


def _parse_pfcwd_stats(dut):
    """
    Parse 'show pfcwd stat' output into a lookup dictionary.

    Returns:
        dict: {(port, queue): {'status': str, 'storm_detect_count': int, 'restored_count': int}}
    """
    pfcwd_stat_output = dut.show_and_parse('show pfcwd stats')
    stats_dict = {}

    for item in pfcwd_stat_output:
        port, queue = item['queue'].split(':')
        storm_detect_count, restored_count = item['storm detected/restored'].split('/')
        stats_dict[(port, int(queue))] = {
            'status': item['status'],
            'storm_detect_count': int(storm_detect_count),
            'restored_count': int(restored_count)
        }

    return stats_dict


def _get_storm_test_ports(storm_hndle):
    """
    Extract list of (port, queue) tuples from storm handle.

    Returns:
        list: [(port, queue), ...]
    """
    ports = []
    for peer in storm_hndle.peer_params.keys():
        fanout_intfs = storm_hndle.peer_params[peer]['intfs'].split(',')
        device_conn = storm_hndle.fanout_graph[peer]['device_conn']
        queue_idx = storm_hndle.storm_handle[peer].pfc_queue_idx

        for intf in fanout_intfs:
            test_port = device_conn[intf]['peerport']
            ports.append((test_port, queue_idx))

    return ports


def verify_all_ports_pfc_storm_in_expected_state(dut, storm_hndle, expected_state, selected_test_ports,
                                                 baseline_counters=None, threshold_percentage=100,
                                                 stormed_ports_list=None, test_ports_info=None):
    """Verify if threshold percentage of ports reached expected PFC storm state."""
    if dut.facts['asic_type'] == 'vs':
        return True

    # Get all ports to check and current stats
    ports_to_check = _get_storm_test_ports(storm_hndle)

    # Filter to only ports with background traffic if selected_test_ports is provided
    if selected_test_ports:
        ports_to_check = [(p, q) for p, q in ports_to_check if p in selected_test_ports]
        logger.debug(f"Filtered to {len(ports_to_check)} ports with background traffic")

    # For restore, only check ports that actually stormed
    if expected_state == "restore" and stormed_ports_list:
        ports_to_check = [(p, q) for p, q in ports_to_check if p in stormed_ports_list]
        logger.info(f"Restore: checking {len(ports_to_check)}/{len(stormed_ports_list)} stormed ports")

    pfcwd_stats_dict = _parse_pfcwd_stats(dut)

    # Verify each port
    ports_in_expected_state = 0
    # Track the per-port result so the shared-address adjustment below can recompute both
    # the numerator and the denominator consistently.
    port_results = {}
    for test_port, queue_idx in ports_to_check:
        port_stats = pfcwd_stats_dict.get((test_port, queue_idx))

        if not port_stats:
            continue

        current_detect_count = port_stats['storm_detect_count']
        current_restored_count = port_stats['restored_count']
        current_status = port_stats['status']

        is_in_expected_state = False
        if expected_state == "storm":
            # For storm state verification, check if detect_count increased since baseline
            # OR if port is currently in storm status with detect_count >= baseline
            baseline_detect = baseline_counters.get(test_port, 0)
            if (current_detect_count > baseline_detect or
                    ("storm" in current_status and current_detect_count >= baseline_detect and
                     current_detect_count > current_restored_count)):
                logger.debug(f"Port {test_port} queue {queue_idx} has new storm detection "
                             f"(baseline={baseline_detect}, current={current_detect_count}, "
                             f"status={current_status})")
                is_in_expected_state = True
        else:  # restore
            if ("storm" not in current_status) and (current_detect_count == current_restored_count):
                is_in_expected_state = True

        if is_in_expected_state:
            ports_in_expected_state += 1
            if expected_state == "storm" and stormed_ports_list is not None and test_port not in stormed_ports_list:
                stormed_ports_list.append(test_port)
        else:
            logger.debug(f"Port {test_port}:{queue_idx} not in {expected_state} state")

        port_results[test_port] = port_results.get(test_port, False) or is_in_expected_state

    total_ports = len(ports_to_check)
    if total_ports == 0:
        logger.warning("No ports found to verify")
        return False

    # The DUT selects the egress port from the destination address, so ports that share a
    # test_neighbor_addr cannot each receive the routed background traffic: it ends up on
    # whichever port owns the neighbor entry or wins the LAG hash, and the remaining ports
    # can never build the egress queue occupancy that PFCWD needs. The test setup hands out
    # one address per port wherever it can, but some topologies cannot be fixed (for
    # example a PortChannel whose neighbor min-links cannot be relaxed). Report those ports
    # loudly, and count each group of ports sharing an address as one effective port so the
    # denominator matches what the traffic can actually reach.
    if expected_state == "storm" and test_ports_info:
        addr_to_ports = {}
        for port, _queue_idx in ports_to_check:
            addr = (test_ports_info.get(port, {}) or {}).get('test_neighbor_addr')
            addr_to_ports.setdefault(addr, set()).add(port)
        shared = {addr: sorted(ports) for addr, ports in addr_to_ports.items()
                  if addr and len(ports) > 1}
        if shared:
            logger.error("These ports share a neighbor address, so only one port per group can "
                         "be driven into a storm and the rest are not really covered: %s", shared)
            effective_total = 0
            effective_success = 0
            for addr, ports in addr_to_ports.items():
                if addr and len(ports) > 1:
                    effective_total += 1
                    effective_success += 1 if any(port_results.get(p, False) for p in ports) else 0
                else:
                    effective_total += len(ports)
                    effective_success += sum(1 for p in ports if port_results.get(p, False))
            logger.info("Adjusting for shared neighbor addresses: ports_in_expected_state %d->%d, "
                        "total_ports %d->%d", ports_in_expected_state, effective_success,
                        total_ports, effective_total)
            ports_in_expected_state = effective_success
            total_ports = effective_total

    success_percentage = (ports_in_expected_state / total_ports) * 100
    logger.info(f"{ports_in_expected_state}/{total_ports} ports ({success_percentage:.1f}%) "
                f"in '{expected_state}' state (threshold: {threshold_percentage}%)")

    return success_percentage >= threshold_percentage


def get_pfc_storm_baseline_counters(dut, storm_hndle):
    """Capture baseline storm detect counters to avoid false positives from stale counters."""
    baseline = {}
    if dut.facts['asic_type'] == 'vs':
        return baseline

    stats_dict = _parse_pfcwd_stats(dut)
    ports_to_check = _get_storm_test_ports(storm_hndle)

    for test_port, queue_idx in ports_to_check:
        port_stats = stats_dict.get((test_port, queue_idx))
        baseline[test_port] = port_stats['storm_detect_count'] if port_stats else 0
        logger.debug(f"Baseline {test_port}:{queue_idx} = {baseline[test_port]}")

    return baseline


def parser_show_pfcwd_stat(dut, select_port, select_queue):
    """
    CLI "show pfcwd stats" output:
    admin@bjw-can-7060-1:~$ show pfcwd stats
            QUEUE    STATUS    STORM DETECTED/RESTORED    TX OK/DROP    RX OK/DROP    TX LAST OK/DROP    RX LAST OK/DROP # noqa: E501
    -------------  --------  -------------------------  ------------  ------------  -----------------  ----------------- # noqa: E501
    Ethernet112:4       N/A                        2/2       100/100       100/100              100/0              100/0 # noqa: E501
    admin@bjw-can-7060-1:~$
    """
    logger.info("port {} queue {}".format(select_port, select_queue))
    pfcwd_stat_output = dut.show_and_parse('show pfcwd stats')

    pfcwd_stat = []
    for item in pfcwd_stat_output:
        port, queue = item['queue'].split(':')
        if port != select_port or int(queue) != int(select_queue):
            continue
        storm_detect_count, restored_count = item['storm detected/restored'].split('/')
        tx_ok_count, tx_drop_count = item['tx ok/drop'].split('/')
        rx_ok_count, rx_drop_count = item['rx ok/drop'].split('/')
        tx_last_ok_count, tx_last_drop_count = item['tx last ok/drop'].split('/')
        rx_last_ok_count, rx_last_drop_count = item['rx last ok/drop'].split('/')

        parsed_dict = {
            'port': port,
            'queue': queue,
            'status': item['status'],
            'storm_detect_count': storm_detect_count,
            'restored_count': restored_count,
            'tx_ok_count': tx_ok_count,
            'tx_drop_count': tx_drop_count,
            'rx_ok_count': rx_ok_count,
            'rx_drop_count': rx_drop_count,
            'tx_last_ok_count': tx_last_ok_count,
            'tx_last_drop_count': tx_last_drop_count,
            'rx_last_ok_count': rx_last_ok_count,
            'rx_last_drop_count': rx_last_drop_count
        }
        pfcwd_stat.append(parsed_dict)

    return pfcwd_stat


def pfcwd_show_status(duthost, output_string):
    """
    Get pfcwd status

    Args:
        duthost: AnsibleHost instance for DUT
        output_string: string to be printed

    Returns:
        pfcwd status
    """
    logger.debug("pfcwd_show_status: {}".format(output_string))

    cmd = "show pfc counters"
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("execute cmd {} response: \n{}".format(cmd, cmd_response.get('stdout', None)))

    cmd = "show pfcwd config"
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("execute cmd {} response: \n{}".format(cmd, cmd_response.get('stdout', None)))

    cmd = "show pfcwd stats"
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("execute cmd {} response: \n{}".format(cmd, cmd_response.get('stdout', None)))

    cmd = "grep \"{}\" /var/log/syslog".format("PFC Watchdog")
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("execute cmd {} response: \n{}".format(cmd, cmd_response.get('stdout', None)))

    return


def send_tx_egress(traffic_inst, action, verify, async_mode=False, pkt_count=None):
    """Send traffic from the Rx port toward the Tx (egress) port and optionally verify
    that the expected PFC watchdog action (forward/drop) is observed on egress."""
    logger.info("Check for egress {} on Tx port {} (verify={})".format(action, traffic_inst.pfc_wd_test_port, verify))
    dst_port = "[" + str(traffic_inst.pfc_wd_test_port_id) + "]"
    if action == "forward" and isinstance(traffic_inst.pfc_wd_test_port_ids, list):
        dst_port = "".join(str(traffic_inst.pfc_wd_test_port_ids)).replace(',', '')
    ptf_params = {'router_mac': traffic_inst.router_mac,
                  'vlan_mac': traffic_inst.vlan_mac,
                  'queue_index': traffic_inst.pfc_queue_index,
                  'pkt_count': pkt_count or traffic_inst.pfc_wd_test_pkt_count,
                  'port_src': traffic_inst.pfc_wd_rx_port_id[0],
                  'port_dst': dst_port,
                  'ip_dst': traffic_inst.pfc_wd_test_neighbor_addr,
                  'port_type': traffic_inst.port_id_to_type_map[traffic_inst.pfc_wd_rx_port_id[0]],
                  'wd_action': action if verify else "dontcare",
                  'ip_version': traffic_inst.ip_version}
    if traffic_inst.pfc_wd_rx_port_vlan_id is not None:
        ptf_params['port_src_vlan_id'] = traffic_inst.pfc_wd_rx_port_vlan_id
    if traffic_inst.pfc_wd_test_port_vlan_id is not None:
        ptf_params['port_dst_vlan_id'] = traffic_inst.pfc_wd_test_port_vlan_id
    log_format = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    log_file = "/tmp/pfc_wd.PfcWdTest.{}.log".format(log_format)
    ptf_runner(traffic_inst.ptf, "ptftests", "pfc_wd.PfcWdTest", "ptftests", params=ptf_params,
               log_file=log_file, is_python3=True, async_mode=async_mode)


def shutdown_lag_members(duthost, selected_port, tbinfo, nbrhosts, ports):
    """Shut down all LAG members except the selected port so that PFC watchdog
    testing runs over a single link while keeping the port-channel up
    (min-links=1).

    Multi-asic-aware: uses minigraph_portchannels (frontend port names on both
    single-asic and multi-asic) instead of config_facts['PORTCHANNEL_MEMBER']
    (which on multi-asic is keyed by asic-internal names like Ethernet1/1
    that don't match the frontend names in test_ports/vm_neighbors). All DUT
    config edits go through namespace-aware CLI/sonic-db-cli; no on-disk
    config_db.json edits, so restore can revert via config_reload.
    """
    if ports[selected_port]['test_port_type'] != 'portchannel':
        return None, None, None

    dst_mgfacts = duthost.get_extended_minigraph_facts(tbinfo)
    portChannel = None
    portChannelMembers = []
    for pc_name, pc_meta in dst_mgfacts['minigraph_portchannels'].items():
        if selected_port in pc_meta.get('members', []):
            portChannel = pc_name
            portChannelMembers = list(pc_meta['members'])
            break
    if portChannel is None:
        return None, None, None

    vm_neighbors = dst_mgfacts['minigraph_neighbors']
    peer_device = vm_neighbors[portChannelMembers[0]]['name']
    peer_port = vm_neighbors[portChannelMembers[0]]['port']
    vm_host = nbrhosts[peer_device]['host']

    neigh_port_channel = None
    min_links = None
    if isinstance(vm_host, EosHost):
        neigh_port_channels = vm_host.eos_command(
            commands=['show port-channel | json'])['stdout'][0]["portChannels"]
        for po_name, po_config in neigh_port_channels.items():
            for member in po_config['activePorts']:
                if member == peer_port:
                    neigh_port_channel = po_name
                    min_links = len(po_config['activePorts'])
                    break
        vm_host.eos_config(lines=['port-channel min-links 1'],
                           parents=[f'int {neigh_port_channel}'])

    # Namespace-aware CLI option: '' on single-asic, '-n asicN' on multi-asic.
    ns = duthost.get_port_asic_instance(selected_port).cli_ns_option
    # Drop min-links to 1 so the LAG stays up while N-1 members are shut.
    duthost.shell(
        f"sonic-db-cli {ns} CONFIG_DB hset 'PORTCHANNEL|{portChannel}' min_links 1")
    for port in portChannelMembers:
        if port == selected_port:
            continue
        duthost.shell(f"sudo config interface {ns} shutdown {port}")

    return vm_host, neigh_port_channel, min_links


def restore_original_config(duthost, selected_port, vm_host, neigh_port_channel, min_links, ports):
    """Revert LAG/min-links edits made by shutdown_lag_members.

    Since shutdown_lag_members modifies running CONFIG_DB only (no on-disk
    edits), config_reload from the on-disk config_db is sufficient to bring
    members back up and restore the original min_links.
    """
    if ports[selected_port]['test_port_type'] != 'portchannel':
        return

    if isinstance(vm_host, EosHost):
        vm_host.eos_config(lines=[f'port-channel min-links {min_links}'],
                           parents=[f'int {neigh_port_channel}'])

    config_reload(duthost, config_source='config_db', safe_reload=True,
                  check_intf_up_ports=True, wait_for_bgp=True)


def _is_multi_member_lag(duthost, port, ports):
    if ports[port]['test_port_type'] != 'portchannel':
        return False
    pc_members = duthost.config_facts(
        host=duthost.hostname, source="persistent"
    )['ansible_facts'].get('PORTCHANNEL_MEMBER', {})
    return any(port in members and len(members) > 1 for members in pc_members.values())


@pytest.fixture(scope='module')
def manage_lag_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, nbrhosts, setup_pfc_test):
    """LAG config resource manager for PFCwd tests.

    Setup: shuts down extra LAG members so only the selected port remains active.
    Teardown: restores the original config_db; runs even on test failure.
    Yields (vm_host, neigh_port_channel, min_links). Skips setup/teardown when
    the selected port is not in a multi-member portchannel.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    ports = setup_pfc_test['selected_test_ports']
    port = list(ports.keys())[0]

    if not _is_multi_member_lag(duthost, port, ports):
        yield None, None, None
        return

    vm_host, neigh_port_channel, min_links = shutdown_lag_members(
        duthost, port, tbinfo, nbrhosts, ports)
    try:
        yield vm_host, neigh_port_channel, min_links
    finally:
        restore_original_config(duthost, port, vm_host, neigh_port_channel, min_links, ports)


def _get_neighbor_portchannel(mg_facts, nbrhosts, member):
    """Look up the neighbor port-channel that `member` belongs to.

    Read-only, so that the caller can decide whether a PortChannel is safe to touch
    before anything is changed.

    Returns:
        tuple: (vm_host, neigh_port_channel, configured_min_links), where
            configured_min_links is None when the neighbor has no min-links configured.
            All three are None when the neighbor is not an EOS host or cannot be found.
    """
    vm_neighbors = mg_facts['minigraph_neighbors']
    if member not in vm_neighbors:
        return None, None, None

    peer_device = vm_neighbors[member]['name']
    peer_port = vm_neighbors[member]['port']
    vm_host = nbrhosts.get(peer_device, {}).get('host')
    # Only EOS neighbors are supported. A SONiC neighbor derives min-links from its member
    # count (see ansible/roles/sonicv2/templates/teamd.j2), so removing a member would take
    # its PortChannel - and the BGP session running on it - down.
    if not isinstance(vm_host, EosHost):
        return None, None, None

    neigh_port_channels = vm_host.eos_command(
        commands=['show port-channel | json'])['stdout'][0]["portChannels"]
    for po_name, po_config in neigh_port_channels.items():
        if peer_port not in po_config['activePorts']:
            continue
        # Read the configured value rather than the current member count, otherwise a
        # port-channel configured with min-links 3 out of 4 members would come back with
        # the stricter min-links 4.
        running_config = vm_host.eos_command(
            commands=[f'show running-config interfaces {po_name}'])['stdout'][0]
        match = re.search(r'port-channel min-links (\d+)', str(running_config))
        return vm_host, po_name, int(match.group(1)) if match else None

    return None, None, None


def new_portchannel_split_state():
    """Build the empty state container for split_multi_member_portchannels()."""
    return {'split_ports': [], 'neighbor_min_links': [], 'touched_portchannels': [],
            'ptf_sysctl_changed': False, 'ip_version': None, 'prefixlen': None}


def split_multi_member_portchannels(duthost, ptfhost, tbinfo, nbrhosts, test_ports, ip_version,
                                    split_state):
    """Give every PortChannel member port a neighbor address of its own.

    parse_pc_list() assigns the PortChannel's single BGP peer address to all of its
    members, so the DUT routes the PTF background traffic to that one next hop and the LAG
    hash picks a single member. The other members receive the PFC pause frames but never
    build any egress queue occupancy, so they cannot be driven into a PFC storm and the
    test cannot cover them individually.

    Keep the first member inside the PortChannel - so the PortChannel, its IP and its BGP
    session stay up - and break the remaining members out into routed interfaces, each with
    its own /30 (or /126) towards the PTF port facing it. test_ports is updated in place so
    that the background traffic is addressed per physical port instead of per PortChannel.

    Args:
        split_state: state container from new_portchannel_split_state(), updated in place
            as changes are made so that restore_multi_member_portchannels() can revert a
            partially applied setup.
    """
    if duthost.facts['asic_type'] == 'vs':
        return

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if ip_version == "IPv4":
        pool = ipaddress.ip_network(PFCWD_MEMBER_SUBNET_IPV4)
        prefixlen = 30
    else:
        pool = ipaddress.ip_network(PFCWD_MEMBER_SUBNET_IPV6)
        prefixlen = 126

    split_state['ip_version'] = ip_version
    split_state['prefixlen'] = prefixlen
    subnets = pool.subnets(new_prefix=prefixlen)
    for pc_name, pc_meta in mg_facts['minigraph_portchannels'].items():
        members = [member for member in pc_meta.get('members', []) if member in test_ports]
        if len(members) < 2:
            continue

        vm_host, neigh_pc, neigh_min_links = _get_neighbor_portchannel(mg_facts, nbrhosts, members[0])
        if vm_host is None:
            logger.warning("Leaving %s alone: its neighbor port-channel could not be relaxed, so "
                           "removing a member would take the PortChannel down", pc_name)
            continue

        asic = duthost.get_port_asic_instance(members[0])
        ns = asic.cli_ns_option
        # The PortChannel is about to be left with a single member, so make sure that
        # neither side takes it down.
        split_state['touched_portchannels'].append(pc_name)
        duthost.shell(f"sonic-db-cli {ns} CONFIG_DB hset 'PORTCHANNEL|{pc_name}' min_links 1")
        split_state['neighbor_min_links'].append((vm_host, neigh_pc, neigh_min_links))
        vm_host.eos_config(lines=['port-channel min-links 1'], parents=[f'int {neigh_pc}'])

        for member in members[1:]:
            subnet = next(subnets, None)
            pytest_assert(subnet is not None,
                          "Ran out of addresses in {} for the PortChannel members".format(pool))
            dut_addr = subnet[1]
            ptf_addr = subnet[2]
            port_info = test_ports[member]
            ptf_port = "eth{}".format(port_info['test_port_id'])

            duthost.shell(f"sudo config portchannel {ns} member del {pc_name} {member}")
            duthost.shell(f"sudo config interface {ns} ip add {member} {dut_addr}/{prefixlen}")
            split_state['split_ports'].append({'port': member, 'portchannel': pc_name,
                                               'ptf_port': ptf_port, 'ptf_addr': str(ptf_addr),
                                               'swss': asic.get_docker_name('swss'),
                                               'port_info': port_info,
                                               'orig_neighbor_addr': port_info['test_neighbor_addr'],
                                               'orig_port_type': port_info['test_port_type']})
            if ip_version == "IPv4":
                ptfhost.command(f"ifconfig {ptf_port} {ptf_addr} netmask {subnet.netmask}")
            else:
                ptfhost.command(f"ip -6 addr add {ptf_addr}/{prefixlen} dev {ptf_port}")

            port_info['test_neighbor_addr'] = str(ptf_addr)
            port_info['test_port_type'] = 'interface'
            logger.info("Split %s out of %s: DUT %s/%s, PTF %s %s",
                        member, pc_name, dut_addr, prefixlen, ptf_port, ptf_addr)

    if not split_state['split_ports']:
        return

    if ip_version == "IPv4":
        # Set arp_ignore=1 so each PTF interface only responds to ARP for its own IP.
        # Without this, Linux's weak host model causes all interfaces to respond to ARP
        # requests for any local IP, polluting the DUT's ARP table.
        split_state['ptf_sysctl_changed'] = True
        ptfhost.command("sysctl -w net.ipv4.conf.all.arp_ignore=1")
        ptfhost.command("sysctl -w net.ipv4.conf.all.arp_announce=2")

    # Resolve the neighbors only after every address is in place, so that each request
    # gets a single answer.
    for entry in split_state['split_ports']:
        if ip_version == "IPv4":
            duthost.command("docker exec -i {} arping {} -c 3".format(entry['swss'], entry['ptf_addr']))
        else:
            duthost.command("docker exec -i {} ping -6 -c 3 {}".format(entry['swss'], entry['ptf_addr']))


def restore_multi_member_portchannels(duthost, ptfhost, split_state):
    """Revert split_multi_member_portchannels(), including a partially applied setup.

    Every DUT edit goes through the CLI and only touches the running CONFIG_DB, so
    reloading the on-disk config_db restores the PortChannel membership, the member IPs
    and min_links in one step.
    """
    if not (split_state['split_ports'] or split_state['neighbor_min_links'] or
            split_state['touched_portchannels']):
        return

    for entry in split_state['split_ports']:
        # setup_pfc_test is module scoped, so put the addressing back in the dict as well
        # as on the DUT, otherwise anything running later in this module would work from
        # addresses the config_reload below has already removed.
        entry['port_info']['test_neighbor_addr'] = entry['orig_neighbor_addr']
        entry['port_info']['test_port_type'] = entry['orig_port_type']
        if split_state['ip_version'] == "IPv4":
            ptfhost.command("ifconfig {} 0.0.0.0".format(entry['ptf_port']),
                            module_ignore_errors=True)
        else:
            ptfhost.command("ip -6 addr del {}/{} dev {}".format(
                entry['ptf_addr'], split_state['prefixlen'], entry['ptf_port']),
                module_ignore_errors=True)

    if split_state['ptf_sysctl_changed']:
        ptfhost.command("sysctl -w net.ipv4.conf.all.arp_ignore=0", module_ignore_errors=True)
        ptfhost.command("sysctl -w net.ipv4.conf.all.arp_announce=0", module_ignore_errors=True)

    # The DUT must be reloaded even if putting a neighbor back fails, otherwise the next
    # test module inherits a PortChannel with its members broken out.
    try:
        for vm_host, neigh_pc, neigh_min_links in split_state['neighbor_min_links']:
            if neigh_min_links is None:
                vm_host.eos_config(lines=['no port-channel min-links'], parents=[f'int {neigh_pc}'])
            else:
                vm_host.eos_config(lines=[f'port-channel min-links {neigh_min_links}'],
                                   parents=[f'int {neigh_pc}'])
    finally:
        config_reload(duthost, config_source='config_db', safe_reload=True,
                      check_intf_up_ports=True, wait_for_bgp=True)
