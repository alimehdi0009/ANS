"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/bin/env python3

from mininet.topo import Topo
from mininet.node import Node
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class LinuxRouter(Node):

	def config(self,**params):
		super(LinuxRouter,self).config(**params)
		self.cmd('sysctl net.ipv4.ip_forward=1')
		
	def terminate(self):
		self.cmd('sysctl net.ipv4.ip_forward=0')
		super(LinuxRouter,self).terminate()


class NetworkTopo(Topo):

    def __init__(self):

        Topo.__init__(self)

        # Build the specified network topology here
        
        
        
        #internal hosts
    
        h1 = self.addHost('h1',ip='10.0.1.2/24',defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2',ip='10.0.1.3/24',defaultRoute='via 10.0.1.1')
        
        #switch s1
        
        s1 = self.addSwitch('s1',cls=OVSKernelSwitch)
        
        #router
        r1=self.addHost('r1',cls=LinuxRouter,ip='10.0.1.1')
        
        #switch s2
        s2 = self.addSwitch('s2',cls=OVSKernelSwitch)
        
        #internet host
        
        ext = self.addHost('ext',ip='192.168.1.123/24',defaultRoute='via 192.168.1.1')
        
        #server
        
        ser = self.addHost("ser",ip='10.0.2.2/24',defaultRoute='via 10.0.2.1')
        
	#link host h1 with switch s1
        self.addLink(h1,s1,cls=TCLink,bw=15,delay=10)
        self.addLink(h2,s1,cls=TCLink,bw=15,delay=10)
        self.addLink(s1,r1,cls=TCLink,bw=15,delay=10,params2={'ip':'10.0.1.1/24'})
        self.addLink(s2,r1,cls=TCLink,bw=15,delay=10,params2={'ip':'10.0.2.1/24'})
        self.addLink(s2,ser,cls=TCLink,bw=15,delay=10)
        
        self.addLink(ext,r1,cls=TCLink,bw=15,delay=10,params2={'ip':'192.168.1.1/24'})
	
		
	
	
def run():
	topo = NetworkTopo()
	net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)

	#host_ext=net.get('ext')
	#router_r1=net.get('r1')
	
	#nat = net.addNAT(name='nat0', connect=True, inNamespace=False, ip='192.168.1.1')
	
	#net.addLink(router_r1,nat,cls=TCLink,bw=15,delay=10)
	#net.addLink(nat,host_ext,cls=TCLink,bw=15,delay=10)
	
	net.addController(
	        'c1', 
	        controller=RemoteController, 
	        ip="127.0.0.1", 
	        port=6653)
	
	net.start()
	CLI(net)
	net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
