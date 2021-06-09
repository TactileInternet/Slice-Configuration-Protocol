#!/usr/bin/env python2
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
from p4_mininet import P4Switch, P4Host
import random
import argparse
from time import sleep
import subprocess
import sys
import os

parser = argparse.ArgumentParser(description='Dynamic Network Slicing Demo - 4 nodes topology')
parser.add_argument('--json', help='Path to JSON config file', type=str, action="store", required=True)
parser.add_argument('--p4info', help='Path to P4info file', type=str, action="store", required=True)
parser.add_argument('--cpu-port', help='An optional veth to use as the CPU port', type=str, action="store", required=False)
parser.add_argument('--grpc-port', help='GRPC server port for table updates', type=int, action="store", default=50051)
parser.add_argument('--controller', dest='controller', help='Used controller (NoSlicing, SDNSlicing; P4Slicing)', action="store", default='P4Slicing')
parser.add_argument('-m', dest='monitoring', help='Monitoring interval for the controller application', type=int, action="store", default=1)
parser.add_argument('-d', dest='directory', default='test', help='Path to the output directory. (default: test/)')
parser.add_argument('-n', dest='name', default='test', help='Name of the output directory. (default: test)')

args = parser.parse_args()

class Switch4Topo(Topo):
    def __init__(self, sw_path, json_path, grpc_port, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        num_sw = 4
        switches=[]
        hostsArray=[]
        for s in range(1, num_sw+1):
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

        self.addLink(switches[0], switches[1]) 
        self.addLink(switches[0], switches[2])
        self.addLink(switches[1], switches[3])
        self.addLink(switches[2], switches[3])
        
	t1 = self.addHost('t1', ip = "200.0.0.10/24", mac = 'ff:04:00:00:00:01')
        self.addLink(switches[0],t1)
        t2 = self.addHost('t2', ip = "200.0.1.10/24", mac = 'ff:04:00:00:00:02')
        self.addLink(switches[3],t2)                

	hosts = [3, 5]       
	for h in hosts:
            hostsArray.append(self.addHost('h%d' % h,
                                ip = "10.0.%d.10/24" % h,
                                mac = '00:04:00:00:00:%02x' %h))
        self.addLink(hostsArray[0], switches[1])
        self.addLink(hostsArray[1], switches[3])


def main():
    num_hosts = 0
    path = args.directory+"/"+args.name
    #try:
    #    os.mkdir(args.directory)
    #    os.mkdir(path)
     
    topo = Switch4Topo("simple_switch_grpc",
                            args.json,
                            args.grpc_port)
    
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
		  link = TCLink,
                  controller = None)
    net.start()

    hosts = [3, 5]       
    for n in hosts:
        h = net.get('h%d' % n)
        h.defaultIntf().rename("eth0")
        h.setDefaultRoute("dev eth0 via 10.0.%d.1" % n)
    
    for n in range(1,3):
        h = net.get('t%d' % n)
        h.defaultIntf().rename("eth0")
        h.setDefaultRoute("dev eth0 via 200.0.%d.1" % (n-1))
    
    sleep(5)
    print "Starting mininet!"
    print args;
    
    print "Ready !"
    
    os.system('sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1')
    os.system('sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1')
    #kill any other controller processes that might be running
    os.system('sudo pkill -f contoller') 
    #os.system('./run_controller.sh'+' '+str(args.controller)+' '+args.json+' '+args.p4info+' '+str(args.monitoring))
    #os.system('tcpdump -i s1-eth1 ip and udp -w '+path+'/clients_trace.pcap &')
    #os.system('tcpdump -i s5-eth1 ip and udp -w '+path+'/servers_trace.pcap &')

    #sleep(20) 
	
    t1 = net.get('t1')
    t2 = net.get('t2')
    h3 = net.get('h3')
    h5 = net.get('h5')
    sleep(2)
	
    #h3.cmd('ping 10.10.5.10 -c 1')
    #inform the controller about all the slices you wish to use
    #t1.cmd('ping 200.0.1.10 -Q 1 -c 3')
    #t1.cmd('ping 200.0.1.10 -Q 2 -c 3')
    #t1.cmd('ping 200.0.1.10 -Q 3 -c 3')
    #t1.cmd('ping 200.0.1.10 -Q 4 -c 3')
    #h5.cmd('iperf3 -s -B 10.10.4.10 > '+path+'/h4server &2>1 &')
    
    #t2.cmd('./server > '+path+'/t2server &2>1 &')
    
    #t1.cmd('./client > '+path+'/t1client &2>1 &')
    
    #h3.cmd('iperf3 -t 250 -c 10.10.5.10 -i 0.3 -B 10.10.3.10 > '+path+'/h2client &2>1 &')
    #sleep(300)
    CLI( net )

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()

