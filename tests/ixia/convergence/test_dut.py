import pytest
import time

def test_bgpconf(duthost,ptfhost):
    BGP_multipaths=2
    duthost=duthosts[rand_one_dut_hostname]
    output=duthost.shell('show ip interface')
    print(output)
    IPs=['30.1.1.1/24','31.1.1./24','32.1.1.1/24']
    duthost.shell('sudo config interface ip add Ethernet20 {}'.format(IPs[0]))
    duthost.shell('sudo config interface ip add Ethernet24 {}'.format(IPs[1]))
    duthost.shell('sudo config interface ip add Ethernet28 {}'.format(IPs[2]))
    
    def checkInterfaceStatus(IPs):
        for i in IPs:
            result=duthost.command('show ip interface | grep {}'.format(IPs[0]))
            if not 'up' in result:
                raise Exception('Interface is {} is not administratively up'.format(result.split(' ')[0]))
            time.sleep(5)
    checkInterfaceStatus(IPs)

    print('Configuring BGP')
    ptfhost.command('docker start bgp')
    duthost.shell('vtysh')
    duthost.shell('configure terminal')
    duthost.shell('router bgp 65100')
    duthost.shell('maximum-paths {}'.format(BGP_multipaths))
    duthost.shell('bgp bestpath as-path multipath-relax')
    duthost.shell('neighbor 31.1.1.2 remote-as 65200')
    duthost.shell('neighbor 32.1.1.2 remote-as 65200')
    duthost.shell('no auto-summary')
    duthost.shell('address-family ipv4 unicast')
    duthost.shell('neighbor 31.1.1.2 activate')
    duthost.shell('neighbor 32.1.1.2 activate')
    duthost.shell('redistribute connected')
    duthost.shell('exit')
    duthost.shell('exit')
    duthost.shell('exit')
