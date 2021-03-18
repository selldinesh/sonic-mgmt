from tests.common.ixia.ixia_fixtures import snappi_api
from tests.common.ixia.ixia_fixtures import (
    ixia_api_serv_ip, ixia_api_serv_port, tgen_ports)
from files.helper import run_bgp_convergence_test
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts, fanout_graph_facts)
import pytest

@pytest.mark.parametrize('multipath',[3])
@pytest.mark.parametrize('convergence_test_iterations',[1])
def test_bgp_convergence(snappi_api,
                         duthost,
                         tgen_ports,
                         conn_graph_facts,
                         fanout_graph_facts,
                         multipath,
                         convergence_test_iterations):

    """
    Topo:
    TGEN1 --- DUT --- TGEN(2..N)

    Steps:
    1) Create BGP config on DUT and TGEN respectively
    2) Create a flow from TGEN1 to (N-1) TGEN ports
    3) Send Traffic from TGEN1 to (N-1) TGEN ports having the same route range
    4) Simulate link failure by bringing down one of the (N-1) TGEN Ports
    5) Calculate the packet loss duration for convergence time
    6) Clean up the BGP config on the dut

    Verification:
    1) Send traffic without flapping any link 
        Result: Should not observe traffic loss 
    2) Flap one of the N TGEN link
        Result: The traffic must be routed via rest of the ECMP paths and should not observe traffic loss

    Args:
        snappi_api (pytest fixture): Snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        multipath: ECMP value
        convergence_test_iterations: number of iterations the link failure test has to be run for a port
    """
    #convergence_test_iterations and multipath values can be modified as per user preference
    run_bgp_convergence_test(snappi_api,
                             duthost,
                             tgen_ports,
                             convergence_test_iterations,
                             multipath)
