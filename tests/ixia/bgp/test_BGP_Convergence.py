import pytest
import snappi
import time
from tabulate import tabulate
from statistics import mean
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,fanout_graph_facts
from tests.common.ixia.common_helpers import get_vlan_subnet, get_addrs_in_subnet,get_peer_ixia_chassis
from tests.common.ixia.ixia_helpers import IxiaFanoutManager, get_tgen_location
from tests.common.ixia.ixia_fixtures import tgen_ports,snappi_api
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
logger = logging.getLogger(__name__)

DUT_AS_NUM = 65100
TGEN_AS_NUM = 65200
BGP_TYPE = 'ebgp'
PORT_COUNT=6
MPATH=PORT_COUNT-1

def test_ip_conf(duthost,tgen_ports):
    ports= []
    for i in range(0,PORT_COUNT):
        intf_config = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'interface %s' "
            "-c 'ip address %s/%s' "
        )
        intf_config %= (tgen_ports[i]['peer_port'],tgen_ports[i]['peer_ip'],tgen_ports[i]['prefix'])
        duthost.shell(intf_config)

def test_bgp_conf(duthost,tgen_ports):
    bgp_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'bgp bestpath as-path multipath-relax' "
        "-c 'maximum-paths %s' "
        "-c 'exit' "
    )
    bgp_config %= (DUT_AS_NUM,MPATH)
    duthost.shell(bgp_config)
    for i in range(0,PORT_COUNT):
        bgp_config_neighbor = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'neighbor %s remote-as %s' "
        "-c 'address-family ipv4 unicast' "
        "-c 'neighbor %s activate' "
        "-c 'exit' "
        )        
        bgp_config_neighbor %= (DUT_AS_NUM,tgen_ports[i]['ip'],TGEN_AS_NUM,tgen_ports[i]['ip'])
        logger.info('Configuring BGP Neighbor %s' %tgen_ports[i]['ip'])
        duthost.shell(bgp_config_neighbor)


def test_bgp_convergence(duthost,snappi_api,tgen_ports):
    """
    1.Configure IPv4 EBGP sessions between the test ports
    2.Advertise IPv4 routes
    3.Simulate link flap on the rx ports and get the convergence values
    """
    config = snappi_api.config()
    for i in range(1,PORT_COUNT+1):
        config.ports.port(name='Test Port %d'%i,location=tgen_ports[i-1]['location'])
        config.devices.device(name='Topology %d'%i,container_name=config.ports[i-1].name,device_count=1)
    
    config.options.port_options.location_preemption = True

    def confLayer1():
        for i in range(1,PORT_COUNT+1):
            layer1 = config.layer1.layer1()[-1]
            layer1.name = '%s port settings'%config.ports[i-1].name
            layer1.port_names = [config.ports[i-1].name]
            layer1.ieee_media_defaults = False
            layer1.auto_negotiation.rs_fec = False
            layer1.auto_negotiation.link_training = False
            layer1.speed= "speed_100_gbps"
            layer1.auto_negotiate = False

    confLayer1()

    def createTopo():
        config.devices[0].ethernet.name='Ethernet 1'
        config.devices[0].ethernet.ipv4.name='IPv4 1'
        config.devices[0].ethernet.ipv4.address.value=tgen_ports[0]['ip']
        config.devices[0].ethernet.ipv4.gateway.value=tgen_ports[0]['peer_ip']
        config.devices[0].ethernet.ipv4.prefix.value=24
        rx_flow_name=[]
        for i in range(2,PORT_COUNT+1):
            Ethernet=config.devices[i-1].ethernet
            Ethernet.name='Ethernet %d'%i
            IPv4=Ethernet.ipv4
            IPv4.name='IPv4 %d'%i
            IPv4.address.value=tgen_ports[i-1]['ip']
            IPv4.gateway.value=tgen_ports[i-1]['peer_ip']
            IPv4.prefix.value=31
            BGPv4=IPv4.bgpv4
            BGPv4.name='BGP %d'%i
            BGPv4.as_type=BGP_TYPE
            BGPv4.dut_ipv4_address.value=tgen_ports[i-1]['peer_ip']
            BGPv4.as_number.value=TGEN_AS_NUM
            RouteRange=BGPv4.bgpv4_route_ranges.bgpv4routerange()[-1]
            RouteRange.name="Network Group %d"%i
            RouteRange.address_count="1000"
            RouteRange.address.value="200.1.0.1"
            RouteRange.prefix.value="32"
            rx_flow_name.append(RouteRange.name)
        return rx_flow_name
    
    rx_flows=createTopo()
    flow = config.flows.flow(name='convergence_test')[-1]
    flow.tx_rx.device.tx_names = [config.devices[0].name]
    flow.tx_rx.device.rx_names = rx_flows
    flow.size.fixed = "1024"
    flow.rate.percentage = "100"
    snappi_api.set_config(config)
    rx_port_names=[]
    for i in range(1,len(config.ports)):
        rx_port_names.append(config.ports[i].name)
    
    def get_flow_stats(snappi_api):
        request = snappi_api.metrics_request()
        request.flow.flow_names = []
        return snappi_api.get_metrics(request).flow_metrics

    def is_port_rx_stopped(snappi_api, port_name):
        """
        Returns true if port is down
        """
        req = snappi_api.metrics_request()
        req.port.port_names = [port_name]
        port_stats = snappi_api.get_metrics(req).port_metrics
        if int(port_stats[0].frames_rx_rate) == 0:
            return True
        return False

    def getAvgDPDPConvergenceTime(portName,iter):
        table,avg=[],[]
        for i in range(0,iter):
            logger.info('|---- {} Link Flap Iteration : {} ----|'.format(portName,i+1))
            
            #Start Traffic
            logger.info('Starting Traffic')
            ts = snappi_api.transmit_state()
            ts.state = ts.START
            response=snappi_api.set_transmit_state(ts)
            assert(len(response.errors)) == 0
            time.sleep(30)
            flow_stats=get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0

            #Link Flap
            logger.info('Simulating Link Failure on {} link'.format(portName))
            ls = snappi_api.link_state()
            ls.port_names = [portName]
            ls.state = ls.DOWN
            response=snappi_api.set_link_state(ls)
            assert(len(response.errors)) == 0
            time.sleep(15)
            assert is_port_rx_stopped(snappi_api,portName) == True
            flow_stats=get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0
            logger.info(tx_frame_rate)
            
            # Stop traffic
            logger.info('Stopping Traffic')
            ts = snappi_api.transmit_state()
            ts.state = ts.STOP
            response=snappi_api.set_transmit_state(ts)
            assert(len(response.errors)) == 0
            time.sleep(5)
            flow_stats=get_flow_stats(snappi_api)
            tx_frames = flow_stats[0].frames_tx
            rx_frames = sum([fs.frames_rx for fs in flow_stats])
            
            # Calculate Convergence
            dp_convergence = (tx_frames - rx_frames) * 1000 / tx_frame_rate
            logger.info("DP/DP Convergence Time: {} ms".format(int(dp_convergence)))  
            avg.append(int(dp_convergence))
            logger.info('Simulating Link Up on {} at the end of iteration {}'.format(portName,i+1))
            
            #Link up
            ls.state = ls.UP
            response=snappi_api.set_link_state(ls)
            assert(len(response.errors)) == 0
        table.append('%s Link Failure'%portName)
        table.append(iter)
        table.append(mean(avg))
        return table
    table=[]
    flap_iterations=1
    #Running link flap test on all the rx ports
    for i in range(0,len(rx_port_names)):
        table.append(getAvgDPDPConvergenceTime(rx_port_names[i],flap_iterations))
    columns=['Event Name','Iterations','Avg Calculated DP/DP Convergence Time(ms)']
    logger.info("\n%s" % tabulate(table,headers=columns,tablefmt="psql"))

def test_cleanupConf(duthost,tgen_ports):
    logger.info('Cleaning Up Interface and BGP config')
    bgp_config_cleanup = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no router bgp %s' "
    )
    bgp_config_cleanup %= (DUT_AS_NUM)
    duthost.shell(bgp_config_cleanup)
    for i in range(0,PORT_COUNT):
        intf_config_cleanup = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'interface %s' "
            "-c 'no ip address %s/%s' "
        )
        intf_config_cleanup %= (tgen_ports[i]['peer_port'],tgen_ports[i]['peer_ip'],tgen_ports[i]['prefix'])
        duthost.shell(intf_config_cleanup)
    logger.info('Convergence Test Completed')
