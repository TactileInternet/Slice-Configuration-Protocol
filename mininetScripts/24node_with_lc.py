from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
from p4_mininet import P4Switch, P4Host
#from p4runtime_switch import P4RuntimeSwitch
import random
import argparse
from time import sleep
import subprocess
import sys
import os

parser = argparse.ArgumentParser(description='Dynamic Network Slicing Demo - 24 nodes topology')
parser.add_argument('--json', help='Path to JSON config file', type=str, action="store", required=True)
parser.add_argument('--p4info', help='Path to P4info file', type=str, action="store", required=True)
parser.add_argument('--cpu-port', help='An optional veth to use as the CPU port', type=str, action="store", required=False)
parser.add_argument('--grpc-port', help='GRPC server port for table updates', type=int, action="store", default=50051)
parser.add_argument('--controller', dest='controller', help='Used controller (NoSlicing, SDNSlicing; P4Slicing)', action="store", default='P4Slicing')
parser.add_argument('-m', dest='monitoring', help='Monitoring interval for the controller application', type=int, action="store", default=1)
parser.add_argument('-d', dest='directory', default='test', help='Path to the output directory. (default: test/)')
parser.add_argument('-n', dest='name', default='test', help='Name of the output directory. (default: test)')

args = parser.parse_args()


class Switch24Topo(Topo):
    def __init__(self, sw_path, json_path, grpc_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        num_sw = 24
        switches=[]
        hostsArray=[]
				
        for s in range(1, 25):
            name = 's'+str(s)
            switches.append(self.addSwitch(name,
                                sw_path = sw_path,
                                json_path = json_path,
                                grpc_port = grpc_port+s-1,
                                device_id = s+1,
                                cpu_port = args.cpu_port))

        lc = self.addHost('lc', mac = 'bb:bb:bb:bb:bb:bb') #local controller
        for s in range(0, num_sw):
                self.addLink(switches[s], lc)

        self.addLink( switches[0], switches[1])
        self.addLink( switches[0], switches[5])
        self.addLink( switches[1], switches[2])
        self.addLink( switches[1], switches[5])
        self.addLink( switches[2], switches[6])
        self.addLink( switches[2], switches[3])
        self.addLink( switches[2], switches[4])
        self.addLink( switches[3], switches[4])
        self.addLink( switches[3], switches[6])
        self.addLink( switches[4], switches[7])
        self.addLink( switches[6], switches[7])
        self.addLink( switches[6], switches[8])
        self.addLink( switches[5], switches[6])
        self.addLink( switches[5], switches[8])
        self.addLink( switches[5], switches[10])
        self.addLink( switches[7], switches[9])
        self.addLink( switches[8], switches[9])
        self.addLink( switches[8], switches[10])
        self.addLink( switches[8], switches[11])
        self.addLink( switches[9], switches[12])
        self.addLink( switches[9], switches[13])
        self.addLink( switches[10], switches[18])
        self.addLink( switches[10], switches[14])
        self.addLink( switches[11], switches[12])
        self.addLink( switches[11], switches[15])
        self.addLink( switches[12], switches[16])
        self.addLink( switches[12], switches[13])
        self.addLink( switches[13], switches[17])
        self.addLink( switches[14], switches[15])
        self.addLink( switches[14], switches[19])
        self.addLink( switches[15], switches[21])
        self.addLink( switches[15], switches[20])
        self.addLink( switches[16], switches[21])
        self.addLink( switches[16], switches[22])
        self.addLink( switches[16], switches[17])
        self.addLink( switches[17], switches[23])
        self.addLink( switches[18], switches[19])
        self.addLink( switches[19], switches[20])
        self.addLink( switches[20], switches[21])
        self.addLink( switches[21], switches[22])
        self.addLink( switches[15], switches[16])
        self.addLink( switches[22], switches[23])

        t1 = self.addHost('t1', ip = "200.0.0.10/24", mac = 'ff:04:00:00:00:01')
        self.addLink(switches[1],t1)
        t2 = self.addHost('t2', ip = "200.0.1.10/24", mac = 'ff:04:00:00:00:02')
        self.addLink(switches[21],t2)


def main():
    num_hosts = 4

    topo = Switch24Topo("simple_switch_grpc",
                            args.json,
                            args.grpc_port)
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
		  link = TCLink,
                  controller = None)
    net.start()

    for n in xrange(2):
        h = net.get('t%d' % (n + 1))
        # h.setARP(sw_addr[n], sw_mac[n])
        h.defaultIntf().rename("eth0")
        h.setDefaultRoute("dev eth0 via 200.0.%d.1" % n)
    
    #sleep(5)
    print "Starting mininet!"
    print args;
    
    print "Ready !"
    
    os.system('sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    os.system('sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    #kill any other controller processes that might be running
    os.system('sudo pkill -f controller') 
    #os.system('./run_controller.sh'+' '+str(args.controller)+' '+args.json+' '+args.p4info+' '+str(args.monitoring))
    #os.system('tcpdump -i s1-eth1 ip and udp -w '+path+'/clients_trace.pcap &')
    #os.system('tcpdump -i s5-eth1 ip and udp -w '+path+'/servers_trace.pcap &')
    
 
    #sleep(20) 	
    #t1 = net.get('t1')
    #t2 = net.get('t2')
    
    #h3 = net.get('h3')
    #h5 = net.get('h5')

    #h3.cmd('ping 10.10.5.10 -c 1') 
    #inform the central controller about all the slices we want to use
    #t1.cmd('ping 200.0.1.10 -Q 1 -c 3')
    #t1.cmd('ping 200.0.1.10 -Q 2 -c 3')
    #t1.cmd('ping 200.0.1.10 -Q 3 -c 3')
    #t1.cmd('ping 200.0.1.10 -Q 4 -c 3')
    
    #h5.cmd('iperf3 -s -B 10.10.5.10 > '+path+'/h5server &2>1 &')
    
    #t2.cmd('./server > '+path+'/t2server &2>1 &')
    
    #t1.cmd('./client > '+path+'/t1client &2>1 &')
    
    #h3.cmd('iperf3 -t 250 -c 10.10.5.10 -i 0.3 -B 10.10.3.10 > '+path+'/h3client &2>1 &')
    #sleep(300)
    CLI( net )

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()

