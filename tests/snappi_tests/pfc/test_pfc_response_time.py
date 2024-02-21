import pytest

from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts                      # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config       # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa F401

from tests.snappi_tests.pfc.files.helper import run_pfc_response_time_test

pytestmark = [pytest.mark.topology('tgen')]


@pytest.mark.parametrize('intf_type', ['IP'])
def test_response_time(snappi_api,                   # noqa F811
                       snappi_testbed_config,        # noqa F811
                       conn_graph_facts,             # noqa F811
                       fanout_graph_facts,           # noqa F811
                       duthosts,
                       rand_one_dut_hostname,
                       rand_one_dut_portname_oper_up,
                       lossless_prio_list,           # noqa F811
                       lossy_prio_list,              # noqa F811
                       prio_dscp_map,
                       intf_type):               # noqa F811
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        intf_type (pytest paramenter): IP or VLAN interface type
    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    test_prio_list = [3]
    bg_prio_list = [4]
    run_pfc_response_time_test(api=snappi_api,
                               testbed_config=testbed_config,
                               port_config_list=port_config_list,
                               conn_data=conn_graph_facts,
                               fanout_data=fanout_graph_facts,
                               duthost=duthost,
                               dut_port=dut_port,
                               global_pause=False,
                               pause_prio_list=test_prio_list,
                               test_prio_list=test_prio_list,
                               bg_prio_list=bg_prio_list,
                               prio_dscp_map=prio_dscp_map,
                               test_traffic_pause=False,
                               intf_type=intf_type,)