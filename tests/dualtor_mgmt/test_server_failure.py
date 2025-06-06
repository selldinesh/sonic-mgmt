import logging
import pytest
import random

from tests.common.dualtor.mux_simulator_control import toggle_simulator_port_to_upper_tor, \
                                                       simulator_flap_counter, simulator_server_down, \
                                                       toggle_all_simulator_ports                       # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.dual_tor_utils import show_muxcable_status                                    # noqa: F401
from tests.common.dualtor.dual_tor_common import active_active_ports                                    # noqa: F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                                   # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                             # noqa: F401
from tests.common.dualtor.dual_tor_common import CableType
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup                    # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                          # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                          # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_fanouthosts, fanout_lower_tor_port_control    # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_fanouthosts, fanout_upper_tor_port_control    # noqa: F401
from tests.common.dualtor.dual_tor_utils import show_muxcable_status  # noqa: F401, F811
from tests.common.dualtor.nic_simulator_control import simulator_server_down_active_active              # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_garp_service, \
                                                run_icmp_responder                                      # noqa: F401
from tests.common.utilities import wait_until
from tests.common.dualtor.icmp_responder_control import shutdown_icmp_responder                         # noqa: F401
from tests.common.dualtor.icmp_responder_control import start_icmp_responder                            # noqa: F401
from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.platform.interface_utils import expect_interface_status
from tests.common.dualtor.constants import UPPER_TOR

pytestmark = [
    pytest.mark.topology('dualtor'),
    pytest.mark.usefixtures('run_garp_service', 'run_icmp_responder')
]


@pytest.mark.enable_active_active
def test_server_down(cable_type, duthosts, tbinfo, active_active_ports, active_standby_ports,               # noqa: F811
                     simulator_flap_counter, simulator_server_down, toggle_simulator_port_to_upper_tor,     # noqa: F811
                     loganalyzer, validate_active_active_dualtor_setup, upper_tor_host, lower_tor_host,     # noqa: F811
                     simulator_server_down_active_active):                                                  # noqa: F811
    """
    Verify that mux cable is not toggled excessively.
    """
    def upper_tor_mux_state_verification(state, health):
        mux_state_upper_tor = show_muxcable_status(upper_tor_host)
        return (mux_state_upper_tor[test_iface]['status'] == state and
                mux_state_upper_tor[test_iface]['health'] == health)

    def lower_tor_mux_state_verfication(state, health):
        mux_state_lower_tor = show_muxcable_status(lower_tor_host)
        return (mux_state_lower_tor[test_iface]['status'] == state and
                mux_state_lower_tor[test_iface]['health'] == health)

    if loganalyzer:
        for analyzer in list(loganalyzer.values()):
            analyzer.ignore_regex.append(
                r".*ERR swss#orchagent: :- setState: State transition from active to active is not-handled"
            )

    if cable_type == CableType.active_standby:
        test_iface = random.choice(active_standby_ports)
        logging.info("Selected %s interface %s to test", cable_type, test_iface)
        # Set upper_tor as active
        toggle_simulator_port_to_upper_tor(test_iface)
        pytest_assert(wait_until(30, 1, 0, upper_tor_mux_state_verification, 'active', 'healthy'),
                      "mux_cable status is unexpected. Should be (active, healthy). Test can't proceed. ")
        mux_flap_counter_0 = simulator_flap_counter(test_iface)

        simulator_server_down(test_iface)

        # Verify mux_cable state on upper_tor is active
        pytest_assert(wait_until(20, 1, 0, upper_tor_mux_state_verification, 'active', 'unhealthy'),
                      "mux_cable status is unexpected. Should be (active, unhealthy)")
        # Verify mux_cable state on lower_tor is standby
        pytest_assert(wait_until(30, 1, 0, lower_tor_mux_state_verfication, 'standby', 'unhealthy'),
                      "mux_cable status is unexpected. Should be (standby, unhealthy)")
        # Verify that mux_cable flap_counter should be no larger than 3
        # lower_tor(standby) -> active -> standby
        # upper_tor(active) -> active
        # The toggle from both tor may be overlapped and invisible
        mux_flap_counter_1 = simulator_flap_counter(test_iface)
        pytest_assert(mux_flap_counter_1 - mux_flap_counter_0 <= 3,
                      "The mux_cable flap count should be no larger than 3 ({})"
                      .format(mux_flap_counter_1 - mux_flap_counter_0))

    elif cable_type == CableType.active_active:
        test_iface = random.choice(active_active_ports)
        logging.info("Selected %s interface %s to test", cable_type, test_iface)

        pytest_assert(upper_tor_mux_state_verification('active', 'healthy'),
                      "mux_cable status is unexpected. Should be (active, healthy)")
        pytest_assert(lower_tor_mux_state_verfication('active', 'healthy'),
                      "mux_cable status is unexpected. Should be (active, healthy)")

        simulator_server_down_active_active(test_iface)

        pytest_assert(wait_until(30, 1, 0, upper_tor_mux_state_verification, 'standby', 'unhealthy'),
                      "mux_cable status is unexpected. Should be (standby, unhealthy)")
        pytest_assert(wait_until(30, 1, 0, lower_tor_mux_state_verfication, 'standby', 'unhealthy'),
                      "mux_cable status is unexpected. Should be (standby, unhealthy)")


@pytest.mark.enable_active_active
def test_server_reboot(request, cable_type, tbinfo,                                # noqa: F811
                       start_icmp_responder, shutdown_icmp_responder,              # noqa: F811
                       active_standby_ports, active_active_ports,                  # noqa: F811
                       upper_tor_host, lower_tor_host,                             # noqa: F811
                       toggle_all_simulator_ports,                                 # noqa: F811
                       fanout_upper_tor_port_control,                              # noqa: F811
                       fanout_lower_tor_port_control):                             # noqa: F811

    """
    Test verifies that TOR health returns back to healthy status after a server reboot.
    """
    def _check_consistency(duthost):
        ret = show_muxcable_status(duthost)
        return all((status.get("hwstatus") == "consistent" and
                    status.get("health") == "healthy") for status in ret.values())

    if cable_type == CableType.active_standby:
        interface_name = random.choice(active_standby_ports)
        # Set upper_tor as active
        toggle_all_simulator_ports(UPPER_TOR)
        verify_tor_states(expected_active_host=upper_tor_host,
                          expected_standby_host=lower_tor_host, cable_type=cable_type)

        pytest_assert(expect_interface_status(upper_tor_host, interface_name, 'up'),
                      f'{interface_name} on upper ToR must be up')
        pytest_assert(expect_interface_status(lower_tor_host, interface_name, 'up'),
                      f'{interface_name} on lower ToR must be up')
        shutdown_icmp_responder()

        # simulate server reboot by turning off all fanout ports on both the ToRs
        shutdown_upper, restart_upper = fanout_upper_tor_port_control
        shutdown_lower, restart_lower = fanout_lower_tor_port_control
        shutdown_upper()
        shutdown_lower()
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, upper_tor_host, interface_name, 'down'),
                      f'{interface_name} on upper ToR is expected to be down after server shutdown')
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, lower_tor_host, interface_name, 'down'),
                      f'{interface_name} on lower ToR is expected to be down after server shutdown')
        restart_upper()
        restart_lower()

        # fanout ports are back on
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, upper_tor_host, interface_name, 'up'),
                      f'{interface_name} on upper ToR is expected to be down after server shutdown')
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, lower_tor_host, interface_name, 'up'),
                      f'{interface_name} on lower ToR is expected to be down after server shutdown')

        start_icmp_responder()
        # The ToRs must then reconcile to a consistent state
        # Upper ToR switches to standby and Lower to active.
        pytest_assert(
            wait_until(60, 5, 0, lambda: _check_consistency(upper_tor_host) and _check_consistency(lower_tor_host)),
            "fail to reconcile to a consistent state"
        )
    elif cable_type == CableType.active_active:
        interface_name = random.choice(active_active_ports)

        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None, cable_type=cable_type)

        pytest_assert(expect_interface_status(upper_tor_host, interface_name, 'up'),
                      f'{interface_name} on upper ToR must be up')
        pytest_assert(expect_interface_status(lower_tor_host, interface_name, 'up'),
                      f'{interface_name} on lower ToR must be up')
        shutdown_icmp_responder()

        verify_tor_states(expected_active_host=None,
                          expected_standby_host=[upper_tor_host, lower_tor_host],
                          expected_standby_health='unhealthy')

        # simulate server reboot by turning off all fanout ports on both the ToRs
        shutdown_upper, restart_upper = fanout_upper_tor_port_control
        shutdown_lower, restart_lower = fanout_lower_tor_port_control
        shutdown_upper()
        shutdown_lower()
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, upper_tor_host, interface_name, 'down'),
                      f'{interface_name} on upper ToR is expected to be down after server shutdown')
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, lower_tor_host, interface_name, 'down'),
                      f'{interface_name} on lower ToR is expected to be down after server shutdown')
        restart_upper()
        restart_lower()

        # fanout ports are back on
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, upper_tor_host, interface_name, 'up'),
                      f'{interface_name} on upper ToR is expected to be down after server shutdown')
        pytest_assert(wait_until(30, 1, 0, expect_interface_status, lower_tor_host, interface_name, 'up'),
                      f'{interface_name} on lower ToR is expected to be down after server shutdown')

        start_icmp_responder()
        verify_tor_states(expected_active_host=[upper_tor_host, lower_tor_host],
                          expected_standby_host=None, cable_type=cable_type)
