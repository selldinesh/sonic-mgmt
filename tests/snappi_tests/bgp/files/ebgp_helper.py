import logging
import json
import json
import time
import pandas as pd
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics      # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.variables import get_macs, get_host_addresses, create_ip_list  
from itertools import count
from rich import print as pr
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from ixnetwork_restpy import SessionAssistant
logger = logging.getLogger(__name__)

RX_SNAPPI_AS_NUM = 10001
DUT_AS_NUM = 10000
TIMEOUT = 30
BGP_TYPE = 'ebgp'
temp_tg_port = dict()
result_list = []
aspaths = [65002, 65003]
max_session_capacity = 0
max_session = 0
min_session = 0
flag = 0
increment = 0
session_count_list = []

def run_ebgp_session_capacity_test(snappi_api,
                                   snappi_ports,
                                   duthost,
                                   snappi_extra_params=None):

    """
    Run eBGP Session Capacity Tests
    """
    config_db = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    global flag
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()
    
    """ Create BGP config on dut and Snappi Config """
    for session_count in count(snappi_extra_params.ebgp_session_count, snappi_extra_params.session_increment):
        global max_session_capacity, increment
        if session_count > snappi_extra_params.max_ebgp_session_count:
            logger.info(' Max eBGP session limit has been reached !!')
            break
        snappi_extra_params.route_ranges = create_ip_list('200.1.1.1', session_count, mask=32)
        snappi_extra_params.tx_host_ips = get_host_addresses(snappi_extra_params.tx_ipv4_subnet + '/' + str(snappi_extra_params.tx_subnet_prefix), 2) # one for ixia , one for dut
        snappi_extra_params.rx_host_ips = get_host_addresses(snappi_extra_params.rx_ipv4_subnet + '/' + str(snappi_extra_params.rx_subnet_prefix), session_count + 1)
        snappi_config = setup_dut_snappi_config(duthost, config_db, snappi_api, snappi_ports, session_count, snappi_extra_params)
        result = verify_results(snappi_api, snappi_config, session_count)
        result_list.append(result)
        flag = flag + result
        if flag == 0:
            continue
        if flag > 0:
            max_session_capacity = session_count - int(snappi_extra_params.session_increment)
            step = int(int(snappi_extra_params.session_increment)/2)
            break

    min_session = max_session_capacity
    max_session = session_count
    logger.info('Reducing eBGP session count as previous iteration encountered loss or protocols didn\'t come up')
    while max_session_capacity >min_session or max_session_capacity < max_session:
        snappi_config = setup_dut_snappi_config(duthost, config_db, snappi_api, snappi_ports, max_session_capacity, snappi_extra_params)
        result = verify_results(snappi_api, snappi_config, max_session_capacity)
        result_list.append(result)
        if result == 0:
            logger.info('Increment Step %Value: {}'.format(step))
            session_count_list.append(max_session_capacity)
            max_session_capacity = max_session_capacity + step
        else:
            logger.info('Decrement Step Value: {}'.format(step))
            max_session_capacity = max_session_capacity - step

        step = int(step/2)
        if step == 0:
            if 0 not in result_list:
                pytest_assert(False, 'BGP test did not run properly on any of the iteration')
            logger.info(session_count_list)
            logger.info('|------------------------------------')
            logger.info("| Max eBGP Session Count is : {}".format(max(session_count_list)))
            logger.info('|------------------------------------')
            break

def setup_dut_snappi_config(duthost,
                            config_db,
                            snappi_api,
                            snappi_ports,
                            session_count,
                            snappi_extra_params):
    """
    Configures BGP on the DUT and Snappi
    """

    logger.info('\n')
    #config_db = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    interfaces = dict()
    loopback_interfaces = dict()
    loopback_interfaces.update({"Loopback0": {}})
    loopback_interfaces.update({"Loopback0|1.1.1.1/32": {}})
    loopback_interfaces.update({"Loopback0|1::1/128": {}})
    tx_interface_name = {snappi_ports[0]['peer_port']: {}}
    rx_interface_name = {snappi_ports[1]['peer_port']: {}}
    tx_interface = {f"{snappi_ports[0]['peer_port']}|{str(snappi_extra_params.tx_host_ips[0])}/{snappi_extra_params.tx_subnet_prefix}": {}}
    rx_interface = {f"{snappi_ports[1]['peer_port']}|{str(snappi_extra_params.rx_host_ips[0])}/{snappi_extra_params.rx_subnet_prefix}": {}}
    interfaces.update(tx_interface_name)
    interfaces.update(tx_interface)
    interfaces.update(rx_interface_name)
    interfaces.update(rx_interface)
    logger.info('{} IPv4 Address:{}'.format(snappi_ports[0]['peer_port'], str(snappi_extra_params.tx_host_ips[0])))
    logger.info('{} IPv4 Address:{}'.format(snappi_ports[1]['peer_port'], str(snappi_extra_params.rx_host_ips[0])))

    # for loop
    bgp_neighbors = dict()
    device_neighbors = dict()
    device_neighbor_metadatas = dict()
    logger.info('Dut AS Number: {}'.format(DUT_AS_NUM))
    logger.info('\n')
    for index,host_ip in enumerate(snappi_extra_params.rx_host_ips[1:]):
        k = RX_SNAPPI_AS_NUM + index
        bgp_neighbor = \
                {
                    str(host_ip):
                    {
                        "admin_status": "up",
                        "asn": str(k),
                        "holdtime": "10",
                        "keepalive": "3",
                        "local_addr": str(snappi_extra_params.rx_host_ips[0]),
                        "name": "snappi-sonic",
                        "nhopself": "0",
                        "rrclient": "0"
                    },
                }
        bgp_neighbors.update(bgp_neighbor)
        device_neighbor = {
                                    snappi_ports[1]['peer_port']:
                                    {
                                        "name": "snappi-sonic",
                                        "port": "Port1"
                                    }
                                }
        device_neighbors.update(device_neighbor)
        device_neighbor_metadata = {
                                       "snappi-sonic":
                                        {
                                            "hwsku": "Snappi",
                                            "mgmt_addr": "172.16.149.206",
                                            "type": "ToRRouter"
                                        }
                                    }
        device_neighbor_metadatas.update(device_neighbor_metadata)
    if "INTERFACE" not in config_db.keys():
        config_db["INTERFACE"] = interfaces
    else:
        config_db["INTERFACE"].update(interfaces)

    if "LOOPBACK_INTERFACE" not in config_db.keys():
        config_db["LOOPBACK_INTERFACE"] = loopback_interfaces
    else:
        config_db["LOOPBACK_INTERFACE"].update(loopback_interfaces)

    if "BGP_NEIGHBOR" not in config_db.keys():
        config_db["BGP_NEIGHBOR"] = bgp_neighbors
    else:
        config_db["BGP_NEIGHBOR"].update(bgp_neighbors)

    if "DEVICE_NEIGHBOR" not in config_db.keys():
        config_db["DEVICE_NEIGHBOR"] = device_neighbors
    else:
        config_db["DEVICE_NEIGHBOR"].update(device_neighbors)

    if 'DEVICE_NEIGHBOR_METADATA' not in config_db.keys():
        config_db["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadatas
    else:
        config_db["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadatas)

    with open("/tmp/temp_config.json", 'w') as fp:
        json.dump(config_db, fp, indent=4)
    duthost.copy(src="/tmp/temp_config.json", dest="/etc/sonic/config_db.json")

    logger.info('Reloading config_db.json to apply IP and BGP configuration on {}'.format(duthost.hostname))
    pytest_assert('Error' not in duthost.shell("sudo config reload -f -y \n")['stderr'],
                  'Error while reloading config in {} !!!!!'.format(duthost.hostname))
    logger.info('Config Reload Successful in {} !!!'.format(duthost.hostname))
    wait(60, "For config reload to complete")
    logger.info('\n')

    config = snappi_api.config()
    for index,snappi_port in enumerate(snappi_ports):
        config.ports.port(name='Test_Port_%d' %
                          index, location=snappi_port['location'])
    d1 = config.devices.device(name='Topology 0')[-1]

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = 'speed_'+str(int(int(snappi_ports[0]['speed'])/1000))+'_gbps'
    layer1.auto_negotiate = False

    # Tx
    eth = config.devices[0].ethernets.add()
    eth.connection.port_name = config.ports[0].name
    eth.name = 'Ethernet_Tx'
    eth.mac = "00:00:00:00:00:01"
    ipv4 = eth.ipv4_addresses.add()
    ipv4.name = 'IPv4 Tx'
    ipv4.address = str(snappi_extra_params.tx_host_ips[1])
    ipv4.gateway = str(snappi_extra_params.tx_host_ips[0])
    ipv4.prefix = int(snappi_extra_params.tx_subnet_prefix)

    # Rx
    rx_flow_name = []
    macs = get_macs("001700000011", session_count)
    rx_flow_name = []
    for index in range(0, session_count):
        d2 = config.devices.device(name='Rx_{}'.format(index))[-1]
        if len(str(hex(index).split('0x')[1])) == 1:
            m = '0'+hex(index).split('0x')[1]
        else:
            m = hex(index).split('0x')[1]
        ethernet_stack = d2.ethernets.add()
        ethernet_stack.connection.port_name = config.ports[1].name
        ethernet_stack.name = 'Ethernet Rx %d' % index
        ethernet_stack.mac = macs[index]
        ipv4_stack = ethernet_stack.ipv4_addresses.add()
        ipv4_stack.name = 'IPv4 Rx %d' % index
        ipv4_stack.address = str(snappi_extra_params.rx_host_ips[index+1])
        ipv4_stack.gateway = str(snappi_extra_params.rx_host_ips[0])
        ipv4_stack.prefix = int(snappi_extra_params.rx_subnet_prefix)
        bgpv4 = config.devices[1].bgp
        bgpv4.router_id = str(snappi_extra_params.rx_host_ips[0])
        bgpv4_int = bgpv4.ipv4_interfaces.add()
        bgpv4_int.ipv4_name = ipv4_stack.name
        bgpv4_peer = bgpv4_int.peers.add()
        bgpv4_peer.name = 'BGP %d' % index
        bgpv4_peer.as_type = 'ebgp'
        bgpv4_peer.peer_address = str(snappi_extra_params.rx_host_ips[0])
        bgpv4_peer.as_number = RX_SNAPPI_AS_NUM + index
        route_range = bgpv4_peer.v4_routes.add(name='Network_Group%s' % index )
        route_range.addresses.add(
        address=str(snappi_extra_params.route_ranges[index]), prefix=32, count=snappi_extra_params.number_of_routes)
        as_path = route_range.as_path
        as_path_segment = as_path.segments.add()
        as_path_segment.type = as_path_segment.AS_SEQ
        as_path_segment.as_numbers = aspaths
        rx_flow_name.append(route_range.name)

    flow = config.flows.flow(name='IPv4 Traffic')[-1]
    flow.tx_rx.device.tx_names = [config.devices[0].name]
    flow.tx_rx.device.rx_names = rx_flow_name
    flow.size.fixed = 1024
    flow.rate.percentage = 100
    flow.metrics.enable = True
    flow.metrics.loss = True
    return config


def get_ti_stats(ixnet):
    tiStatistics = StatViewAssistant(ixnet, 'Traffic Item Statistics')
    tdf = pd.DataFrame(tiStatistics.Rows.RawData, columns=tiStatistics.ColumnHeaders)
    selected_columns = ['Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %', 'Tx Frame Rate', 'Rx Frame Rate']
    tmp = tdf[selected_columns]
    return tmp

def wait_for_bgp_session_up(ixnet, timeout = 60, restart_down = False):
    time.sleep(timeout)
    protocol_summary = StatViewAssistant(ixnet, 'Protocols Summary')
    for row in  protocol_summary.Rows:
        if 'BGP' in row['Protocol Type']:
            logger.info('eBGP Sessions Total : {}'.format(row['Sessions Total']))
            logger.info('eBGP Sessions Up    : {}'.format(row['Sessions Up']))
            if int(row['Sessions Total']) != int(row['Sessions Up']) and restart_down == False:
                logger.info(' All eBGP sessions are not Up in {}s'.format(timeout))
                return False
            elif int(row['Sessions Total']) != int(row['Sessions Up']) and restart_down == True:
                logger.info('|-------FAIL : All eBGP sessions are not Up after Restart Down operation in {}s-----|'.format(timeout))
                return False
    return True




def verify_results(api, snappi_config, session_count):
    global max_session_capacity
    logger.info('\n')
    logger.info('|------  Running test for {} eBGP sessions -----|'.format(session_count))
    logger.info('\n')
    api.set_config(snappi_config)
    ixnet = api._ixnetwork
    logger.info('Starting Protocols ...')
    ixnet.StartAllProtocols()
    logger.info('Cheking eBGP session status ...')
    result = wait_for_bgp_session_up(ixnet, timeout = 180)
    if result is False:
        bgp =  ixnet.Topology.find()[1].DeviceGroup.find()[0].Ethernet.find()[0].Ipv4.find()[0].BgpIpv4Peer.find()[0]
        bgp.RestartDown()
        logger.info('Performing Restart Down on BGP Stack and Checking status ...')
        result = wait_for_bgp_session_up(ixnet, timeout = 180, restart_down = True)
        if result is False:
            return 1
    logger.info('All eBGP sessions are UP !!')
    logger.info('Starting Traffic ...')
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    api.set_control_state(ts)
    wait(30, "For traffic to start")
    flow_metrics = fetch_snappi_flow_metrics(api, ['IPv4 Traffic'])[0]
    if int(flow_metrics.loss) != 0:
        logger.info('|---------FAIL: Loss Observed for {} sessions---------|'.format(session_count))
        logger.info('Dumping Traffic Item statistics :\n {}'.
            format(tabulate(get_ti_stats(ixnet), headers='keys', tablefmt='psql')))
        return 1
    logger.info('PASS: No Loss observed for {} sessions\n'.format(session_count))
    logger.info('Stopping Traffic ...')
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
    api.set_control_state(ts)
    ixnet.StopAllProtocols()
    wait(30, "For traffic and protocol to stop")
    max_session_capacity = session_count
    return 0
