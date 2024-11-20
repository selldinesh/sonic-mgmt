"""
This module allows various snappi based tests to generate various traffic configurations.
"""
from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
import time
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import get_egress_queue_count, pfc_class_enable_vector, \
    get_lossless_buffer_size, get_pg_dropped_packets, \
    sec_to_nanosec, get_pfc_frame_count, packet_capture, get_tx_frame_count, get_rx_frame_count, \
    traffic_flow_mode
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp

from scapy.all import *
import scapy.contrib.mac_control
import pandas as pd
import struct
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

SNAPPI_POLL_DELAY_SEC = 2
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4


def setup_base_traffic_config(testbed_config,
                              port_config_list,
                              port_id):
    """
    Generate base configurations of flows, including test flows, background flows and
    pause storm. Test flows and background flows are also known as data flows.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test

    Returns:
        base_flow_config (dict): base flow configuration containing dut_port_config, tx_mac,
            rx_mac, tx_port_config, rx_port_config, tx_port_name, rx_port_name
            dict key-value pairs (all keys are strings):
                tx_port_id (int): ID of ixia TX port ex. 1
                rx_port_id (int): ID of ixia RX port ex. 2
                tx_port_config (SnappiPortConfig): port config obj for ixia TX port
                rx_port_config (SnappiPortConfig): port config obj for ixia RX port
                tx_mac (str): MAC address of ixia TX port ex. '00:00:fa:ce:fa:ce'
                rx_mac (str): MAC address of ixia RX port ex. '00:00:fa:ce:fa:ce'
                tx_port_name (str): name of ixia TX port ex. 'Port 1'
                rx_port_name (str): name of ixia RX port ex. 'Port 2'
                dut_port_config (list): a list of two dictionaries of tx and rx ports on the peer (switch) side,
                                        and the associated test priorities
                                        ex. [{'Ethernet4':[3, 4]}, {'Ethernet8':[3, 4]}]
    """
    base_flow_config = {}
    rx_port_id = port_id
    tx_port_id_list, _ = select_ports(port_config_list=port_config_list,
                                      pattern="many to one",
                                      rx_port_id=rx_port_id)

    pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
    tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                rx_port_id=rx_port_id)
    pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")
    base_flow_config["rx_port_id"] = rx_port_id
    base_flow_config["tx_port_id"] = tx_port_id

    tx_port_config = next((x for x in port_config_list if x.id == tx_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)
    base_flow_config["tx_port_config"] = tx_port_config
    base_flow_config["rx_port_config"] = rx_port_config

    # Instantiate peer ports in dut_port_config
    dut_port_config = []
    tx_dict = {str(tx_port_config.peer_port): []}
    rx_dict = {str(rx_port_config.peer_port): []}
    dut_port_config.append(tx_dict)
    dut_port_config.append(rx_dict)
    base_flow_config["dut_port_config"] = dut_port_config

    base_flow_config["tx_mac"] = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        base_flow_config["rx_mac"] = rx_port_config.mac
    else:
        base_flow_config["rx_mac"] = tx_port_config.gateway_mac

    base_flow_config["tx_port_name"] = testbed_config.ports[tx_port_id].name
    base_flow_config["rx_port_name"] = testbed_config.ports[rx_port_id].name

    base_flow_config["tx_device_group_name"] = "Device " + testbed_config.ports[tx_port_id].name
    base_flow_config["rx_device_group_name"] = "Device " + testbed_config.ports[rx_port_id].name
    return base_flow_config


def generate_test_flows(testbed_config,
                        test_flow_prio_list,
                        prio_dscp_map,
                        snappi_extra_params):
    """
    Generate configurations of test flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        test_flow_prio_list (list): list of test flow priorities
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    pytest_assert(data_flow_config is not None, "Cannot find data flow configuration")

    for prio in test_flow_prio_list:
        test_flow = testbed_config.flows.flow(name='{} Prio {}'.format(data_flow_config["flow_name"], prio))[-1]
        test_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
        test_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

        eth, ipv4 = test_flow.packet.ethernet().ipv4()
        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
        eth.pfc_queue.value = prio

        ipv4.src.value = base_flow_config["tx_port_config"].ip
        ipv4.dst.value = base_flow_config["rx_port_config"].ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        test_flow.size.fixed = data_flow_config["flow_pkt_size"]
        test_flow.rate.percentage = data_flow_config["flow_rate_percent"]
        if data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
            test_flow.duration.fixed_seconds.seconds = data_flow_config["flow_dur_sec"]
            test_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec
                                                                     (data_flow_config["flow_delay_sec"]))
        elif data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_PACKETS:
            test_flow.duration.fixed_packets.packets = data_flow_config["flow_pkt_count"]
            test_flow.duration.fixed_packets.delay.nanoseconds = int(sec_to_nanosec
                                                                     (data_flow_config["flow_delay_sec"]))

        test_flow.metrics.enable = True
        test_flow.metrics.loss = True

        """ Set flow port config values """
        dut_port_config = base_flow_config["dut_port_config"]
        dut_port_config[0][str(base_flow_config["tx_port_config"].peer_port)].append(int(prio))
        dut_port_config[1][str(base_flow_config["rx_port_config"].peer_port)].append(int(prio))
        base_flow_config["dut_port_config"] = dut_port_config

    snappi_extra_params.base_flow_config = base_flow_config


def generate_background_flows(testbed_config,
                              bg_flow_prio_list,
                              prio_dscp_map,
                              snappi_extra_params):
    """
    Generate background configurations of flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        bg_flow_prio_list (list): list of background flow priorities
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config
    pytest_assert(bg_flow_config is not None, "Cannot find background flow configuration")

    for prio in bg_flow_prio_list:
        bg_flow = testbed_config.flows.flow(name='{} Prio {}'.format(bg_flow_config["flow_name"], prio))[-1]
        bg_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
        bg_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

        eth, ipv4 = bg_flow.packet.ethernet().ipv4()
        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
        eth.pfc_queue.value = prio

        ipv4.src.value = base_flow_config["tx_port_config"].ip
        ipv4.dst.value = base_flow_config["rx_port_config"].ip
        ipv4.priority.choice = ipv4.priority.DSCP
        ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
        ipv4.priority.dscp.ecn.value = (
            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        bg_flow.size.fixed = bg_flow_config["flow_pkt_size"]
        bg_flow.rate.percentage = bg_flow_config["flow_rate_percent"]
        bg_flow.duration.fixed_seconds.seconds = bg_flow_config["flow_dur_sec"]
        bg_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec
                                                               (bg_flow_config["flow_delay_sec"]))

        bg_flow.metrics.enable = True
        bg_flow.metrics.loss = True


def generate_pause_flows(testbed_config,
                         pause_prio_list,
                         global_pause,
                         snappi_extra_params):
    """
    Generate configurations of pause flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        pause_prio_list (list): list of pause priorities
        global_pause (bool): global pause or per priority pause
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    pause_flow_config = snappi_extra_params.traffic_flow_config.pause_flow_config
    pytest_assert(pause_flow_config is not None, "Cannot find pause flow configuration")

    pause_flow = testbed_config.flows.flow(name=pause_flow_config["flow_name"])[-1]
    pause_flow.tx_rx.port.tx_name = testbed_config.ports[base_flow_config["rx_port_id"]].name
    pause_flow.tx_rx.port.rx_name = testbed_config.ports[base_flow_config["tx_port_id"]].name

    if global_pause:
        pause_pkt = pause_flow.packet.ethernetpause()[-1]
        pause_pkt.dst.value = "01:80:C2:00:00:01"
        pause_pkt.src.value = snappi_extra_params.pfc_pause_src_mac if snappi_extra_params.pfc_pause_src_mac \
            else "00:00:fa:ce:fa:ce"
    else:
        pause_time = []
        for x in range(8):
            if x in pause_prio_list:
                pause_time.append(int('ffff', 16))
            else:
                pause_time.append(int('0000', 16))

        vector = pfc_class_enable_vector(pause_prio_list)
        pause_pkt = pause_flow.packet.pfcpause()[-1]
        pause_pkt.src.value = snappi_extra_params.pfc_pause_src_mac if snappi_extra_params.pfc_pause_src_mac \
            else "00:00:fa:ce:fa:ce"
        pause_pkt.dst.value = "01:80:C2:00:00:01"
        pause_pkt.class_enable_vector.value = vector if snappi_extra_params.set_pfc_class_enable_vec else 0
        pause_pkt.pause_class_0.value = pause_time[0]
        pause_pkt.pause_class_1.value = pause_time[1]
        pause_pkt.pause_class_2.value = pause_time[2]
        pause_pkt.pause_class_3.value = pause_time[3]
        pause_pkt.pause_class_4.value = pause_time[4]
        pause_pkt.pause_class_5.value = pause_time[5]
        pause_pkt.pause_class_6.value = pause_time[6]
        pause_pkt.pause_class_7.value = pause_time[7]

    # Pause frames are sent from the RX port of ixia
    pause_flow.rate.pps = pause_flow_config["flow_rate_pps"]
    pause_flow.size.fixed = pause_flow_config["flow_pkt_size"]
    pause_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(
        pause_flow_config["flow_delay_sec"]))

    if pause_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
        pause_flow.duration.fixed_seconds.seconds = pause_flow_config["flow_dur_sec"]
    elif pause_flow_config["flow_traffic_type"] == traffic_flow_mode.CONTINUOUS:
        pause_flow.duration.choice = pause_flow.duration.CONTINUOUS

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True


def aresone_offset(x):
    res = int(float(x) * 0.078125)
    if res >= 20:
        raise Exception('odd time offset value: {} resulted in {} ns'.format(x, res))
    return res


def novus_offset(x):
    res = int(float(x >> 5) * 2.5)
    if res >= 20:
        raise Exception('odd time offset value: {} resulted in {} ns'.format(x, res))
    return res


# aresone - 0.625, novus - 2.5
IXIA_TIME_CONSTANTS = {
    "aresone": aresone_offset,
    "novus": novus_offset
}


def hw_pcap_to_dt(v):
    return pd.to_datetime(int(v * 10**6), unit='ns')


def hw_pcap_to_ns(v):
    return int(v * 10**6)


def decode_hw_ts(p, layer, card):
    if p.haslayer(layer):
        data = bytes(p[layer].payload)[:24]
        s1, s2, s3, s4, s5, s6, offset, p1, p2, p3, seq, ts = struct.unpack("!IIBBBBBBBBII", data)
        if s3 != 0x49 or s4 != 0x78 or s5 != 0x69:
            raise Exception('wrong ixia signature in {}: {}, {}, {}'.format(data, s3, s4, s5))

        t = ts * 20 + IXIA_TIME_CONSTANTS[card](offset)
        return t
    raise Exception('layer {} not present in {}'.format(layer, p))


def hw_pcap_to_dataframe(filename, card, limit=0, type="IP"):
    res = []
    n = 0
    for p in PcapReader(filename):
        if p.haslayer(type):
            res.append({
                "sent": decode_hw_ts(p, type, card),
                "received": hw_pcap_to_ns(p.time),
                "wirelen": p.wirelen,
                "timestamp": hw_pcap_to_dt(p.time),
                "type": "ip",
                "latency": hw_pcap_to_ns(p.time) - decode_hw_ts(p, type, card)
            })
        if p.haslayer(scapy.contrib.mac_control.MACControlClassBasedFlowControl):
            q = p[scapy.contrib.mac_control.MACControlClassBasedFlowControl]
            res.append({
                "received": hw_pcap_to_ns(p.time),
                "wirelen": p.wirelen,
                "timestamp": hw_pcap_to_dt(p.time),
                "type": "pfc",
                "c0_pause_time": q.c0_pause_time,
                "c0_enabled": q.c0_enabled,
            })
        n = n + 1
        if limit and n >= limit:
            break
    return pd.DataFrame.from_records(res)


def run_response_time_test(duthost,
                           api,
                           config,
                           all_flow_names,
                           packet_count,
                           pause_rate,
                           snappi_extra_params):
    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        all_flow_names (list): list of names of all the flows
        packet_count (int): Number of pre pause packets
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        per-flow statistics (list)
    """
    duthost.command('sudo pfcwd stop \n')
    time.sleep(10)
    base_flow_config = snappi_extra_params.base_flow_config

    # Enabling capture
    logger.info("Enabling packet capture on the pre-pause Rx Port ...")
    capture = config.captures.capture()[-1]
    capture.name = "Capture 1"
    capture.port_names = [base_flow_config["tx_port_name"], base_flow_config["rx_port_name"]]
    capture.format = capture.PCAP
    api.set_config(config)

    username = api._username
    ip = api._address
    password = api._password
    test_platform = TestPlatform(ip)
    test_platform.Authenticate("admin", "admin")

    id = test_platform.Sessions.find()[-1].Id
    session = SessionAssistant(IpAddress=ip, UserName=username, SessionId=id, Password=password)
    ixnetwork = session.Ixnetwork
    ixnetwork.Traffic.EnableMinFrameSize = False
    ixnetwork.Traffic.EnableStaggeredStartDelay = False #

    ixnetwork.Globals.Statistics.Advanced.Timestamp.TimestampPrecision = 9
    port1 = ixnetwork.Vport.find(Name=base_flow_config["tx_port_name"])[0]
    port2 = ixnetwork.Vport.find(Name=base_flow_config["rx_port_name"])[0]
    # port2.Type = 'novusHundredGigLan'
    port2.TxMode = 'interleaved'
    port2.Capture.SoftwareEnabled = False
    port2.Capture.DataReceiveTimestamp = 'hwTimestamp'
    port2.Capture.HardwareEnabled = False
    port1.Capture.SoftwareEnabled = False
    port1.Capture.HardwareEnabled = True
    port1.Capture.DataReceiveTimestamp = 'hwTimestamp'
    port1.Capture.Filter.CaptureFilterEnable = True

    port1.Capture.Filter.CaptureFilterPattern = 'pattern1'
    if port1.Name == 'Port 1':
        port1.Capture.FilterPallette.Pattern1 = '15010102'
    else:
        port1.Capture.FilterPallette.Pattern1 = '16010102'
    port1.Capture.FilterPallette.PatternMask1 = 'FFFFFF00'
    port1.Capture.Filter.CaptureFilterExpressionString='P2'

    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    pre_pause_ti = ixnetwork.Traffic.TrafficItem.find(Name='Pre-Pause')[0]
    pre_pause_ti.TransmitMode = 'interleaved'

    # adding endpointset
    pre_pause_ti.ConfigElement.find()[0].TransmissionControl.Type = 'fixedFrameCount'
    pre_pause_ti.ConfigElement.find()[0].TransmissionControl.FrameCount = 100
    pre_pause_ti.EndpointSet.add(Name="Pause Storm", Sources=port2.Protocols.find(),
                                 Destinations=port1.Protocols.find())
    #pause traffic
    ce = pre_pause_ti.ConfigElement.find()[1]
    ce.TransmissionControl.Type = 'continuous'
    
    ce.FrameRate.Rate = pause_rate
    pfc_template = ixnetwork.Traffic.ProtocolTemplate.find(StackTypeId='^pfcPause$')
    ethernet_template = ce.Stack.find(StackTypeId='^ethernet$')
    PFC_stack = ce.Stack.read(ethernet_template.AppendProtocol(pfc_template))
    ethernet_template.Remove()
    PFC_stack.find(StackTypeId='^pfcPause$').Field.find()[4].SingleValue = 8
    PFC_stack.find(StackTypeId='^pfcPause$').Field.find()[5].SingleValue = '0'
    PFC_stack.find(StackTypeId='^pfcPause$').Field.find()[8].SingleValue = 'ffff'

    pre_pause_ti.Generate()
    ixnetwork.Traffic.Apply()
    logger.info("Starting transmit on pause and pre-pause ...")
    pre_pause_ti.StartStatelessTrafficBlocking()
    time.sleep(10)
    pre_pause_ti.StopStatelessTrafficBlocking()
    TI_Statistics = StatViewAssistant(ixnetwork, 'Traffic Item Statistics')
    last_time_stamp = float(TI_Statistics.Rows[1]["Last TimeStamp"].split(':')[-1]) * 1000
    ce.TransmissionControl.StartDelayUnits = 'milliseconds'
    ce.TransmissionControl.StartDelay = int(last_time_stamp)

    logger.info("Starting transmit on test flow ...")
    test_flow_ti = ixnetwork.Traffic.TrafficItem.find(Name='Test Flow Prio 3')[0]
    test_flow_ti.Generate()
    pre_pause_ti.Generate()
    ixnetwork.Traffic.Apply()
    test_flow_ti.StartStatelessTrafficBlocking()
    time.sleep(10)
    # start capture on tx port of test flow
    logger.info("Starting packet capture ...")
    ixnetwork.StartCapture()

    # starting pause and pre-pause
    time.sleep(10)
    logger.info("Starting transmit on pause and pre-pause ...")
    pre_pause_ti.StartStatelessTrafficBlocking()
    TI_Statistics = StatViewAssistant(ixnetwork, 'Traffic Item Statistics')
    t=0
    while True:
        TI_Statistics = StatViewAssistant(ixnetwork, 'Traffic Item Statistics')
        if int(float(TI_Statistics.Rows[0]["Tx Frame Rate"])) == 0:
            logger.info('Test Flow stopped sending packets')
            break
        logger.info('Polling for Test Flow to stop transmitting ...........{} m sec'.format(t * 1000))
        pytest_assert(t<20, 'Test Flow is still transmitting for 10 seconds after starting pre-pause')
        time.sleep(0.05)
        t=t+0.05
    # TI_Statistics = StatViewAssistant(ixnetwork, 'Traffic Item Statistics')
    lastStreamPacketTimestamp = TI_Statistics.Rows[0]["Last TimeStamp"]

    print(' Stopping Traffic')
    ixnetwork.Traffic.StopStatelessTrafficBlocking()
    # Stopping and getting packets
    time.sleep(10)
    logger.info("Stopping packet capture ...")
    ixnetwork.StopCapture()
    time.sleep(20)

    pathp = ixnetwork.Globals.PersistencePath
    res = ixnetwork.SaveCaptureFiles(Arg1=pathp)[0]

    cf = "moveFile.cap"
    session.Session.DownloadFile(res, cf)

    host1_df = hw_pcap_to_dataframe(cf, "novus", 100, "IP")
    logger.info(host1_df)

    lineRate = 100
    ns_per_bit = 1.0 / lineRate
    ns_per_byte = ns_per_bit * 8
    numPrePauseFrames = 1

    prePausePacketSize = pre_pause_ti.ConfigElement.find()[0].FrameSize.FixedSize
    pausePacketTxDelay = numPrePauseFrames * (prePausePacketSize + 20)
    pausePacketTxDelay = pausePacketTxDelay - 20
    pausePacketTxDelay = pausePacketTxDelay - (prePausePacketSize / 2)

    packetTimeOnWire = ns_per_byte * (prePausePacketSize + 20)
    packetDurationOnWire = ns_per_byte * prePausePacketSize

    pd.DataFrame.from_records(host1_df)
    lastPrePausePacketTxTimeStamp = host1_df['sent'].loc[host1_df.index[packet_count - 1]]
    pauseFrameTimestamp = lastPrePausePacketTxTimeStamp + packetTimeOnWire
    pauseFrameTxTimestamp = pauseFrameTimestamp + packetDurationOnWire

    responseTime = float(lastStreamPacketTimestamp.split(':')[-1]) * 1000000000 - pauseFrameTxTimestamp
    logger.info('----------------------------------------------')
    logger.info("Last Pre Pause Timestamp   : {} ns|".format(float(lastPrePausePacketTxTimeStamp)))
    last_data_packet_timestamp = float(lastStreamPacketTimestamp.split(':')[-1])* 1000000000
    logger.info("Last Data Packet Timestamp : {} ns|".format(last_data_packet_timestamp))
    logger.info("Pause Tx Timestamp         : {} ns|".format(pauseFrameTxTimestamp))
    logger.info("Response Time              : {} ns|".format(responseTime))
    logger.info('----------------------------------------------')

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    flow_metrics = api.get_metrics(request).flow_metrics
    logger.info("Stopping transmit on all remaining flows")
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)

    return flow_metrics


def run_traffic(duthost,
                api,
                config,
                data_flow_names,
                all_flow_names,
                exp_dur_sec,
                snappi_extra_params):

    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        per-flow statistics (list)
    """

    api.set_config(config)

    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    pcap_type = snappi_extra_params.packet_capture_type
    base_flow_config = snappi_extra_params.base_flow_config
    switch_tx_lossless_prios = sum(base_flow_config["dut_port_config"][1].values(), [])
    switch_rx_port = snappi_extra_params.base_flow_config["tx_port_config"].peer_port
    switch_tx_port = snappi_extra_params.base_flow_config["rx_port_config"].peer_port
    switch_device_results = None

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Starting packet capture ...")
        cs = api.capture_state()
        cs.port_names = snappi_extra_params.packet_capture_ports
        cs.state = cs.START
        api.set_capture_state(cs)

    logger.info("Starting transmit on all flows ...")
    ts = api.transmit_state()
    ts.state = ts.START
    api.set_transmit_state(ts)

    # Test needs to run for at least 10 seconds to allow successive device polling
    if snappi_extra_params.poll_device_runtime and exp_dur_sec > 10:
        logger.info("Polling DUT for traffic statistics for {} seconds ...".format(exp_dur_sec))
        switch_device_results = {}
        switch_device_results["tx_frames"] = {}
        switch_device_results["rx_frames"] = {}
        for lossless_prio in switch_tx_lossless_prios:
            switch_device_results["tx_frames"][lossless_prio] = []
            switch_device_results["rx_frames"][lossless_prio] = []
        exp_dur_sec = exp_dur_sec + ANSIBLE_POLL_DELAY_SEC  # extra time to allow for device polling
        poll_freq_sec = int(exp_dur_sec / 10)

        for _ in range(10):
            for lossless_prio in switch_tx_lossless_prios:
                switch_device_results["tx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_tx_port,
                                                                                                lossless_prio)[0])
                switch_device_results["rx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_rx_port,
                                                                                                lossless_prio)[0])
            time.sleep(poll_freq_sec)

        logger.info("DUT polling complete")
    else:
        time.sleep(exp_dur_sec)  # no polling required

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = data_flow_names
        flow_metrics = api.get_metrics(request).flow_metrics

        # If all the data flows have stopped
        transmit_states = [metric.transmit for metric in flow_metrics]
        if len(flow_metrics) == len(data_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            logger.info("All test and background traffic flows stopped")
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.capture_state()
        cs.state = cs.STOP
        api.set_capture_state(cs)
        logger.info("Retrieving and saving packet capture to {}.pcapng".format(snappi_extra_params.packet_capture_file))
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    flow_metrics = api.get_metrics(request).flow_metrics
    logger.info("Stopping transmit on all remaining flows")
    ts = api.transmit_state()
    ts.state = ts.STOP
    api.set_transmit_state(ts)

    return flow_metrics, switch_device_results


def verify_pre_pause(flow_metrics,
                     pre_pause_flow_name,
                     pre_pause_packets):
    """
    Verify pause flow statistics i.e. all pause frames should be dropped

    Args:
        flow_metrics (list): per-flow statistics
        pre_pause_flow_name (str): name of the pre pause flow
        pre_pause_packets (int): number of pre pause packets sent
    Returns:
    """
    pre_pause_flow_row = next(metric for metric in flow_metrics if metric.name == pre_pause_flow_name)
    pre_pause_flow_rx_frames = pre_pause_flow_row.frames_rx

    pytest_assert(pre_pause_flow_rx_frames == pre_pause_packets,
                  "Received desired number of pre pause packets")


def verify_pause_flow(flow_metrics,
                      pause_flow_name):
    """
    Verify pause flow statistics i.e. all pause frames should be dropped

    Args:
        flow_metrics (list): per-flow statistics
        pause_flow_name (str): name of the pause flow
    Returns:
    """
    pause_flow_row = next(metric for metric in flow_metrics if metric.name == pause_flow_name)
    pause_flow_tx_frames = pause_flow_row.frames_tx
    pause_flow_rx_frames = pause_flow_row.frames_rx

    pytest_assert(pause_flow_tx_frames > 0 and pause_flow_rx_frames == 0,
                  "All the pause frames should be dropped")


def verify_background_flow(flow_metrics,
                           speed_gbps,
                           tolerance,
                           snappi_extra_params):
    """
    Verify background flow statistics. Background traffic on lossy priorities should not be dropped when there is no
    congestion, else some packets should be dropped if there is congestion.

    Args:
        flow_metrics (list): per-flow statistics
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for background flow deviation
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config

    for metric in flow_metrics:
        if bg_flow_config["flow_name"] not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx

        exp_bg_flow_rx_pkts = bg_flow_config["flow_rate_percent"] / 100.0 * speed_gbps \
            * 1e9 * bg_flow_config["flow_dur_sec"] / 8.0 / bg_flow_config["flow_pkt_size"]
        deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)

        pytest_assert(tx_frames == rx_frames,
                      "{} should not have any dropped packet".format(metric.name))

        pytest_assert(abs(deviation) < tolerance,
                      "{} should receive {} packets (actual {})".format(metric.name, exp_bg_flow_rx_pkts, rx_frames))


def verify_basic_test_flow(flow_metrics,
                           speed_gbps,
                           tolerance,
                           test_flow_pause,
                           snappi_extra_params):
    """
    Verify basic test flow statistics from ixia. Test traffic on lossless priorities should not be dropped regardless
    of whether there is congestion or not.

    Args:
        flow_metrics (list): per-flow statistics
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for test flow deviation
        test_flow_pause (bool): whether test flow is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    test_tx_frames = []
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config

    for metric in flow_metrics:
        if data_flow_config["flow_name"] not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx
        test_tx_frames.append(tx_frames)

        if test_flow_pause:
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "{} should be paused".format(metric.name))
        else:
            pytest_assert(tx_frames == rx_frames,
                          "{} should not have any dropped packet".format(metric.name))

            exp_test_flow_rx_pkts = data_flow_config["flow_rate_percent"] / 100.0 * speed_gbps \
                * 1e9 * data_flow_config["flow_dur_sec"] / 8.0 / data_flow_config["flow_pkt_size"]
            deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          "{} should receive {} packets (actual {})".
                          format(data_flow_config["flow_name"], exp_test_flow_rx_pkts, rx_frames))

    snappi_extra_params.test_tx_frames = test_tx_frames


def verify_in_flight_buffer_pkts(duthost,
                                 flow_metrics,
                                 snappi_extra_params):
    """
    Verify in-flight TX bytes of test flows should be held by switch buffer unless PFC delay is applied
    for when test traffic is expected to be paused

    Args:
        duthost (obj): DUT host object
        flow_metrics (list): per-flow statistics
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    tx_frames_total = sum(metric.frames_tx for metric in flow_metrics if data_flow_config["flow_name"] in metric.name)
    tx_bytes_total = tx_frames_total * data_flow_config["flow_pkt_size"]
    dut_buffer_size = get_lossless_buffer_size(host_ans=duthost)
    headroom_test_params = snappi_extra_params.headroom_test_params
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, "Flow port config is not provided")

    if headroom_test_params is None:
        exceeds_headroom = False
    elif headroom_test_params[1]:
        exceeds_headroom = False
    else:
        exceeds_headroom = True

    if exceeds_headroom:
        pytest_assert(tx_bytes_total > dut_buffer_size,
                      "Total TX bytes {} should exceed DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config[0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(duthost, peer_port, prio)
                pytest_assert(dropped_packets > 0,
                              "Total TX dropped packets {} should be more than 0".
                              format(dropped_packets))
    else:
        pytest_assert(tx_bytes_total < dut_buffer_size,
                      "Total TX bytes {} should be smaller than DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config[0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(duthost, peer_port, prio)
                pytest_assert(dropped_packets == 0,
                              "Total TX dropped packets {} should be 0".
                              format(dropped_packets))


def verify_pause_frame_count_dut(duthost,
                                 test_traffic_pause,
                                 snappi_extra_params):
    """
    Verify correct frame count for pause frames when the traffic is expected to be paused or not
    on the DUT

    Args:
        duthost (obj): DUT host object
        test_traffic_pause (bool): whether test traffic is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')

    for peer_port, prios in dut_port_config[0].items():  # TX PFC pause frames
        for prio in prios:
            pfc_pause_tx_frames = get_pfc_frame_count(duthost, peer_port, prio, is_tx=True)
            if test_traffic_pause:
                pytest_assert(pfc_pause_tx_frames > 0,
                              "PFC pause frames should be transmitted and counted in TX PFC counters for priority {}"
                              .format(prio))
            else:
                # PFC pause frames should not be transmitted when test traffic is not paused
                pytest_assert(pfc_pause_tx_frames == 0,
                              "PFC pause frames should not be transmitted and counted in TX PFC counters")

    for peer_port, prios in dut_port_config[1].items():  # RX PFC pause frames
        for prio in prios:
            pfc_pause_rx_frames = get_pfc_frame_count(duthost, peer_port, prio, is_tx=False)
            if test_traffic_pause:
                pytest_assert(pfc_pause_rx_frames > 0,
                              "PFC pause frames should be received and counted in RX PFC counters for priority {}"
                              .format(prio))
            else:
                # PFC pause frames should not be received when test traffic is not paused
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames should not be received and counted in RX PFC counters")


def verify_tx_frame_count_dut(duthost,
                              snappi_extra_params,
                              tx_frame_count_deviation=0.05,
                              tx_drop_frame_count_tol=5):
    """
    Verify correct frame count for tx frames on the DUT
    (OK and DROPS) when the traffic is expected to be paused on the DUT.
    DUT is polled after it stops receiving PFC pause frames from TGEN.
    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        tx_frame_count_deviation (float): deviation for tx frame count (default to 1%)
        tx_drop_frame_count_tol (int): tolerance for tx drop frame count
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    tgen_tx_frames = snappi_extra_params.test_tx_frames

    # RX frames on DUT must TX once DUT stops receiving PFC pause frames
    for peer_port, _ in dut_port_config[1].items():
        tx_frames, tx_drop_frames = get_tx_frame_count(duthost, peer_port)
        pytest_assert(abs(sum(tgen_tx_frames) - tx_frames) / sum(tgen_tx_frames) <= tx_frame_count_deviation,
                      "Additional frames are transmitted outside of deviation. Possible PFC frames are counted.")
        pytest_assert(tx_drop_frames <= tx_drop_frame_count_tol, "No frames should be dropped")


def verify_rx_frame_count_dut(duthost,
                              snappi_extra_params,
                              rx_frame_count_deviation=0.05,
                              rx_drop_frame_count_tol=5):
    """
    Verify correct frame count for rx frames on the DUT
    (OK and DROPS) when the traffic is expected to be paused on the DUT.
    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        rx_frame_count_deviation (float): deviation for rx frame count (default to 1%)
        rx_drop_frame_count_tol (int): tolerance for tx drop frame count
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    tgen_tx_frames = snappi_extra_params.test_tx_frames

    # TX on TGEN is RX on DUT
    for peer_port, _ in dut_port_config[0].items():
        rx_frames, rx_drop_frames = get_rx_frame_count(duthost, peer_port)
        pytest_assert(abs(sum(tgen_tx_frames) - rx_frames) / sum(tgen_tx_frames) <= rx_frame_count_deviation,
                      "Additional frames are received outside of deviation. Possible PFC frames are counted.")
        pytest_assert(rx_drop_frames <= rx_drop_frame_count_tol, "No frames should be dropped")


def verify_unset_cev_pause_frame_count(duthost,
                                       snappi_extra_params):
    """
    Verify zero pause frames are counted when the PFC class enable vector is not set

    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec

    if not set_class_enable_vec:
        for peer_port, prios in dut_port_config[1].items():
            for prio in prios:
                pfc_pause_rx_frames = get_pfc_frame_count(duthost, peer_port, prio)
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames with no bit set in the class enable vector should be dropped")


def verify_egress_queue_frame_count(duthost,
                                    switch_flow_stats,
                                    test_traffic_pause,
                                    snappi_extra_params,
                                    egress_queue_frame_count_tol=10):
    """
    Verify correct frame count for regular traffic from DUT egress queue

    Args:
        duthost (obj): DUT host object
        switch_flow_stats (dict): switch flow statistics
        test_traffic_pause (bool): whether test traffic is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        egress_queue_frame_count_tol (int): tolerance for egress queue frame count when traffic is expected
                                            to be paused
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec
    test_tx_frames = snappi_extra_params.test_tx_frames

    if test_traffic_pause:
        pytest_assert(switch_flow_stats, "Switch flow statistics is not provided")
        for prio, poll_data in switch_flow_stats["tx_frames"].items():
            mid_poll_index = int(len(poll_data) / 2)
            next_poll_index = mid_poll_index + 1
            mid_poll_egress_queue_count = switch_flow_stats["tx_frames"][prio][mid_poll_index]
            next_poll_egress_queue_count = switch_flow_stats["tx_frames"][prio][next_poll_index]
            pytest_assert(next_poll_egress_queue_count - mid_poll_egress_queue_count <= egress_queue_frame_count_tol,
                          "Egress queue frame count should not increase when test traffic is paused")

    if not set_class_enable_vec and not test_traffic_pause:
        for peer_port, prios in dut_port_config[1].items():
            for prio in range(len(prios)):
                total_egress_packets, _ = get_egress_queue_count(duthost, peer_port, prios[prio])
                pytest_assert(total_egress_packets == test_tx_frames[prio],
                              "Queue counters should increment for invalid PFC pause frames")


def generate_pre_pause_flows(testbed_config,
                              snappi_extra_params,
                              intf_type):
    """
    Generate background configurations of flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        intf_type : IP or VLAN interface type
    """
    base_flow_config = snappi_extra_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config
    pytest_assert(bg_flow_config is not None, "Cannot find background flow configuration")

    bg_flow = testbed_config.flows.flow(name='{}'.format(bg_flow_config["flow_name"]))[-1]
    bg_flow.tx_rx.port.tx_name = testbed_config.ports[base_flow_config["rx_port_id"]].name
    bg_flow.tx_rx.port.rx_name = testbed_config.ports[base_flow_config["tx_port_id"]].name

    eth, ipv4 = bg_flow.packet.ethernet().ipv4()
    if intf_type == 'VLAN' or intf_type == 'vlan':
        eth.src.value = base_flow_config["rx_mac"]
        eth.dst.value = base_flow_config["tx_mac"]
    elif intf_type == 'IP' or intf_type == 'ip':
        eth.src.value = base_flow_config["tx_mac"]
        eth.dst.value = base_flow_config["rx_mac"]
    else:
        pytest_assert(False, "Invalid interface type given")

    ipv4.src.value = base_flow_config["rx_port_config"].ip
    ipv4.dst.value = base_flow_config["tx_port_config"].ip

    bg_flow.size.fixed = bg_flow_config["flow_pkt_size"]
    bg_flow.rate.percentage = bg_flow_config["flow_rate_percent"]
    bg_flow.duration.fixed_packets.packets = bg_flow_config["flow_pkt_count"]
    bg_flow.metrics.enable = True
    bg_flow.metrics.loss = True
