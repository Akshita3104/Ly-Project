"""
Network Topology for DDoS Detection

This module defines the network topology for the DDoS detection system using Mininet.
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class DDoSTopology(Topo):
    """
    Network topology for DDoS detection with multiple slices.
    
    Topology:
    - 3 switches (s1, s2, s3)
    - 6 hosts (h1-h6)
    - 3 slices (high, medium, low priority)
    """
    
    def __init__(self):
        """Create custom topology."""
        Topo.__init__(self)
        
        # Add switches
        s1 = self.addSwitch('s1', dpid='0000000000000001')
        s2 = self.addSwitch('s2', dpid='0000000000000002')
        s3 = self.addSwitch('s3', dpid='0000000000000003')
        
        # Add hosts for high priority slice (h1, h2)
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.1.2/24', mac='00:00:00:00:00:02')
        
        # Add hosts for medium priority slice (h3, h4)
        h3 = self.addHost('h3', ip='10.0.2.1/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.2.2/24', mac='00:00:00:00:00:04')
        
        # Add hosts for low priority slice (h5, h6)
        h5 = self.addHost('h5', ip='10.0.3.1/24', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.3.2/24', mac='00:00:00:00:00:06')
        
        # Add links with different bandwidths for slices
        # High priority slice (10Mbps)
        self.addLink(s1, h1, bw=10, delay='5ms', loss=0)
        self.addLink(s1, h2, bw=10, delay='5ms', loss=0)
        
        # Medium priority slice (5Mbps)
        self.addLink(s2, h3, bw=5, delay='10ms', loss=1)
        self.addLink(s2, h4, bw=5, delay='10ms', loss=1)
        
        # Low priority slice (1Mbps)
        self.addLink(s3, h5, bw=1, delay='20ms', loss=2)
        self.addLink(s3, h6, bw=1, delay='20ms', loss=2)
        
        # Connect switches
        self.addLink(s1, s2, bw=100, delay='1ms', loss=0)
        self.addLink(s2, s3, bw=100, delay='1ms', loss=0)


topos = {'ddos_topo': (lambda: DDoSTopology())}


def run():
    """Create and run the network."""
    topo = DDoSTopology()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1'),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    net.start()
    
    # Add default routes for hosts
    for host in net.hosts:
        host.cmd(f'ip route add default via 10.0.{host.name[1]}.254')
    
    # Start CLI
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
