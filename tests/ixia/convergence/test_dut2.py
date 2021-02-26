def test_bgp_conf(duthost):
    intf1_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'interface Ethernet20' "
        "-c 'ip address 50.10.10.10/24' "
    )
    duthost.command(intf1_config)