import pytest
import time
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import wait
logger = logging.getLogger(__name__)

DUT_AS_NUM = 65100
TGEN_AS_NUM = 65200
BGP_TYPE = 'ebgp'
def run_bgp_convergence_test(snappi_api,
                             duthost,
                             tgen_ports,
                             iteration,
                             multipath):
    """
    Run BGP Convergence test
    
    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
    """
    port_count = multipath+1
    # Create bgp config on dut
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       multipath) 

    # Create bgp config on TGEN 
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        tgen_ports,
                                        port_count)

    # Run the convergence test by flapping all the rx links one by one and calculate the convergence values
    tgen_get_convergence_time(snappi_api,
                              tgen_bgp_config,
                              iteration,
                              multipath)

    # Cleanup the dut configs after getting the convergence numbers
    cleanup_config(duthost,
                   tgen_ports,
                   port_count)


def duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       multipath):
    """
    Configures BGP on the DUT with N-1 ecmp
    
    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
        multipath: ECMP value for BGP config
    """
    for i in range(0,port_count):
        intf_config = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'interface %s' "
            "-c 'ip address %s/%s' "
        )
        intf_config %= (tgen_ports[i]['peer_port'],tgen_ports[i]['peer_ip'],tgen_ports[i]['prefix'])
        logger.info('Configuring IP Address %s' %tgen_ports[i]['ip'])
        duthost.shell(intf_config)
    bgp_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'bgp bestpath as-path multipath-relax' "
        "-c 'maximum-paths %s' "
        "-c 'exit' "
    )
    bgp_config %= (DUT_AS_NUM,multipath)
    duthost.shell(bgp_config)
    for i in range(1,port_count):
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


def __tgen_bgp_config(snappi_api,
                      tgen_ports,
                      port_count):
    """
    Creating  BGP config on TGEN
    
    Args:
        snappi_api (pytest fixture): Snappi API
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count: multipath + 1
    """
    config = snappi_api.config()
    for i in range(1,port_count+1):
        config.ports.port(name = 'Test Port %d'%i,location = tgen_ports[i-1]['location'])
        config.devices.device(name = 'Topology %d'%i)
        config.devices[i-1].container_name = config.ports[i-1].name

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = False
    layer1.auto_negotiation.link_training = False
    layer1.speed = "speed_100_gbps"
    layer1.auto_negotiate = False

    def create_topo():
        config.devices[0].ethernet.name = 'Ethernet 1'
        config.devices[0].ethernet.ipv4.name = 'IPv4 1'
        config.devices[0].ethernet.ipv4.address = tgen_ports[0]['ip']
        config.devices[0].ethernet.ipv4.gateway = tgen_ports[0]['peer_ip']
        config.devices[0].ethernet.ipv4.prefix = 24
        rx_flow_name = []
        for i in range(2,port_count+1):
            ethernet_stack = config.devices[i-1].ethernet
            ethernet_stack.name = 'Ethernet %d'%i
            ipv4_stack = ethernet_stack.ipv4
            ipv4_stack.name = 'IPv4 %d'%i
            ipv4_stack.address = tgen_ports[i-1]['ip']
            ipv4_stack.gateway = tgen_ports[i-1]['peer_ip']
            ipv4_stack.prefix = 31
            bgpv4_stack=ipv4_stack.bgpv4
            bgpv4_stack.name = 'BGP %d'%i
            bgpv4_stack.as_type = BGP_TYPE
            bgpv4_stack.dut_address = tgen_ports[i-1]['peer_ip']
            bgpv4_stack.as_number = TGEN_AS_NUM
            route_range = bgpv4_stack.bgpv4_routes.bgpv4route(name="Network Group %d"%i)[-1]
            route_range.addresses.bgpv4routeaddress(address='200.1.0.1', prefix=32, count=1000, step=1)
            rx_flow_name.append(route_range.name)
        return rx_flow_name
    
    rx_flows = create_topo()
    flow = config.flows.flow(name = 'convergence_test')[-1]
    flow.tx_rx.device.tx_names = [config.devices[0].name]
    flow.tx_rx.device.rx_names = rx_flows
    flow.size.fixed = 1024
    flow.rate.percentage = 100
    response = snappi_api.set_config(config)
    assert(len(response.errors)) == 0
    return config

def tgen_get_convergence_time(snappi_api,
                              config,
                              iteration,
                              multipath):
    """
    Args:
        snappi_api (pytest fixture): Snappi API
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
    """
    rx_port_names = []
    response = snappi_api.set_config(config)
    assert(len(response.errors)) == 0
    for i in range(1,len(config.ports)):
        rx_port_names.append(config.ports[i].name)
    
    def get_flow_stats(snappi_api):
        """
        Args:
            snappi_api (pytest fixture): Snappi API
        """
        request = snappi_api.metrics_request()
        request.flow.flow_names = []
        return snappi_api.get_metrics(request).flow_metrics

    def is_port_rx_stopped(snappi_api,
                           port_name):
        """
        Args:
            snappi_api (pytest fixture): Snappi API
            portName: Name of the port
            Returns true if port is down
        """
        req = snappi_api.metrics_request()
        req.port.port_names = [port_name]
        port_stats = snappi_api.get_metrics(req).port_metrics
        if int(port_stats[0].frames_rx_rate) == 0:
            return True
        return False

    def check_bgp_session_state(multipath):
        """
        Args:
            multipath: ECMP value for BGP config
        """
        req = snappi_api.metrics_request()
        req.bgpv4.column_names = ['sessions_total', 'sessions_up']
        results = snappi_api.get_metrics(req)
        assert len(results.bgpv4_metrics) == multipath
        for i in range(0,multipath):
            assert results.bgpv4_metrics[i].sessions_total == 1
            assert results.bgpv4_metrics[i].sessions_up == 1

    def get_avg_dpdp_convergence_time(portName):
        """
        Args:
            portName: Name of the port
        """
        table,avg = [],[]
        for i in range(0,iteration):
            logger.info('|---- {} Link Flap Iteration : {} ----|'.format(portName,i+1))
            
            #Start Traffic
            logger.info('Starting Traffic')
            ts = snappi_api.transmit_state()
            ts.state = ts.START
            response = snappi_api.set_transmit_state(ts)
            assert(len(response.errors)) == 0
            wait(20,"For Traffic To start")
            check_bgp_session_state(multipath)
            flow_stats = get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0

            #Link Flap
            logger.info('Simulating Link Failure on {} link'.format(portName))
            ls = snappi_api.link_state()
            ls.port_names = [portName]
            ls.state = ls.DOWN
            response = snappi_api.set_link_state(ls)
            assert(len(response.errors)) == 0
            wait(10,"For Link to go down")
            assert is_port_rx_stopped(snappi_api,portName) == True
            flow_stats = get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            logger.info(tx_frame_rate)
            
            # Stop traffic
            logger.info('Stopping Traffic')
            ts = snappi_api.transmit_state()
            ts.state = ts.STOP
            response = snappi_api.set_transmit_state(ts)
            assert(len(response.errors)) == 0
            wait(10,"For Traffic To Stop")
            flow_stats = get_flow_stats(snappi_api)
            assert flow_stats[0].frames_tx_rate == 0
            tx_frames = flow_stats[0].frames_tx
            rx_frames = sum([fs.frames_rx for fs in flow_stats])
            
            # Calculate DPDP Convergence
            dp_convergence = (tx_frames - rx_frames) * 1000 / tx_frame_rate
            logger.info("DP/DP Convergence Time: {} ms".format(int(dp_convergence)))  
            avg.append(int(dp_convergence))
            logger.info('Simulating Link Up on {} at the end of iteration {}'.format(portName,i+1))
            
            #Link up at the end of iteration
            ls.state = ls.UP
            response = snappi_api.set_link_state(ls)
            assert(len(response.errors)) == 0
        table.append('%s Link Failure'%portName)
        table.append(iteration)
        table.append(mean(avg))
        return table
    table = []
    #Iterating link flap test on all the rx ports
    for i in range(0,len(rx_port_names)):
        table.append(get_avg_dpdp_convergence_time(rx_port_names[i]))
    columns = ['Event Name','Iterations','Avg Calculated DP/DP Convergence Time(ms)']
    logger.info("\n%s" % tabulate(table,headers = columns,tablefmt = "psql"))

def cleanup_config(duthost,
                   tgen_ports,
                   port_count):
    """
    Cleaning up dut config at the end of the test
    
    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
    """
    logger.info('Cleaning Up Interface and BGP config')
    bgp_config_cleanup = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'no router bgp %s' "
    )
    bgp_config_cleanup %= (DUT_AS_NUM)
    duthost.shell(bgp_config_cleanup)
    for i in range(0,port_count):
        intf_config_cleanup = (
            "vtysh "
            "-c 'configure terminal' "
            "-c 'interface %s' "
            "-c 'no ip address %s/%s' "
        )
        intf_config_cleanup %= (tgen_ports[i]['peer_port'],tgen_ports[i]['peer_ip'],tgen_ports[i]['prefix'])
        duthost.shell(intf_config_cleanup)
    logger.info('Convergence Test Completed')
