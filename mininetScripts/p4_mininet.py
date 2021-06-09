# Copyright 2019 Belma Turkovic
# 
# NOTICE: THIS FILE HAS BEEN MODIFIED BY BELMA TURKOVIC UNDER COMPLIANCE WITH THE APACHE 2.0 LICENCE FROM THE ORIGINAL WORK 
# OF THE COMPANY Barefoot Networks, Inc. THE FOLLOWING IS THE COPYRIGHT OF THE ORIGINAL DOCUMENT:
#
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info

class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print "**********"
        print self.name
        print "default interface: %s\t%s\t%s" %(
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        )
        print "**********"
        
class P4Switch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__( self, name, sw_path = None, json_path = None,
                  thrift_port = None,
		  grpc_port = None,
                  pcap_dump = False,
                  verbose = False,
                  device_id = None,
                  enable_debugger = False,
                  cpu_port = None,
                  **kwargs ):
        Switch.__init__( self, name, **kwargs )
        assert(sw_path)
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        self.thrift_port = thrift_port
        self.grpc_port = grpc_port
        #self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.cpu_port = cpu_port
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
	    #self.thrift_port = 9090 + device_id
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1

    @classmethod
    def setup( cls ):
        pass

    def start( self, controllers ):
        "Start up a new P4 switch"
        print "Starting P4 switch", self.name
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend( ['-i', str(port) + "@" + intf.name] )
        if self.cpu_port:
            args.extend( ['-i', "64@" + self.cpu_port] )
        if self.thrift_port:
            args.extend( ['--thrift-port', str(self.thrift_port)] )
        
        args.extend( ['--device-id', str(self.device_id)] )
        P4Switch.device_id += 1
        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")
	args.append("--log-flush --log-level trace --log-file %s.log" % self.name)
        if self.grpc_port:
		args.append("-- --grpc-server-addr 0.0.0.0:"+str(self.grpc_port)+" --cpu-port 64")
        print ' '.join(args)

        self.cmd( ' '.join(args) + ' > %s.log 2>&1 &' % self.name)
        #self.cmd( ' '.join(args) + ' > /dev/null 2>&1 &' )

        print "switch has been started"

    def stop( self ):
        "Terminate IVS switch."
        self.output.flush()
        self.cmd( 'kill %' + self.sw_path )
        self.cmd( 'wait' )
        self.deleteIntfs()

    def attach( self, intf ):
        "Connect a data port"
        assert(0)

    def detach( self, intf ):
        "Disconnect a data port"
        assert(0)


