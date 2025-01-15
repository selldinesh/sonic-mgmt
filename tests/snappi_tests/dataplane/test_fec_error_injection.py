from tests.snappi_tests.dataplane.imports import *
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config
from tests.common.snappi_tests.common_helpers import traffic_flow_mode
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]

ErrorTypes = [  'maxConsecutiveUncorrectableWithoutLossOfLink',
                'codeWords',
                'minConsecutiveUncorrectableWithLossOfLink',
                'laneMarkers'
            ]
# ErrorTypes = [
#                 'minConsecutiveUncorrectableWithLossOfLink'
#             ]

@pytest.mark.parametrize('error_type', ErrorTypes)
def test_fec_error_injection(snappi_api,                   # noqa F811
                             snappi_testbed_config,        # noqa F811
                             conn_graph_facts,             # noqa F811
                             fanout_graph_facts,           # noqa F811
                             duthosts,
                             error_type,
                             rand_one_dut_portname_oper_up,
                             rand_one_dut_hostname):               # noqa F811

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    api=snappi_api
    conn_data=conn_graph_facts
    fanout_data=fanout_graph_facts
    snappi_extra_params=None    
     
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()
    port_id = get_dut_port_id(duthost.hostname,
                            dut_port,
                            conn_data,
                            fanout_data)
    
    pytest_assert(port_id is not None,
                'Fail to get ID for port {}'.format(dut_port))
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)
    base_flow = snappi_extra_params.base_flow_config
    test_flow = testbed_config.flows.flow(name='IPv4 Traffic')[-1]
    test_flow.tx_rx.device.tx_names = [testbed_config.devices[0].name]
    test_flow.tx_rx.device.rx_names = [testbed_config.devices[1].name]
    test_flow.metrics.enable = True
    test_flow.metrics.loss = True
    test_flow.size.fixed = 64
    test_flow.rate.percentage = 10
    
    api.set_config(testbed_config) 
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    ixnet = api._ixnetwork
    port1 = ixnet.Vport.find()[0]
    logger.info('|----------------------------------------|')
    logger.info('| Setting FEC Error Type to : {} |'.format(error_type))
    logger.info('|----------------------------------------|')
    port1.L1Config.FecErrorInsertion.ErrorType = error_type
    if error_type == 'codeWords':
        port1.L1Config.FecErrorInsertion.PerCodeword = 16
    port1.L1Config.FecErrorInsertion.Continuous = True

    logger.info('Starting Traffic ...')
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    api.set_control_state(ts)
    wait(10, "For traffic to start")

    logger.info('Starting FEC Error Insertion')
    port1.StartFecErrorInsertion()
    wait(15, "For error insertion to start")
    # TODO For maxConsecutiveUncorrectableWithoutLossOfLink check link state on DUT
    flow_metrics = fetch_snappi_flow_metrics(api, ['IPv4 Traffic'])[0]
    pytest_assert(flow_metrics.frames_tx > 0 and int(flow_metrics.frames_rx_rate) == 0,
                "FAIL: Rx Port did not stop receiving packets after starting FEC Error Insertion")
    logger.info(' .. PASSED : Rx Port stopped receiving packets after starting FEC Error Insertion')
    logger.info('Stopping FEC Error Insertion')
    port1.StopFecErrorInsertion()
    wait(15, "For error insertion to stop")

    flow_metrics = fetch_snappi_flow_metrics(api, ['IPv4 Traffic'])[0]
    pytest_assert(int(flow_metrics.frames_rx_rate) > 0,
                "FAIL: Rx Port did not resume receiving packets after stopping FEC Error Insertion")
    logger.info(' .. PASSED : Rx Port resumed receiving packets after stopping FEC Error Insertion')
    logger.info('Stopping Traffic ...')
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
    api.set_control_state(ts)
    wait(10, "For traffic to stop")

