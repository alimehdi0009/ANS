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

#!/usr/bin/env python3

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

from topo import Fattree
from dijkstra import Dijkistra


class FattreeNet(Topo):
	"""
		Create a fat-tree network in Mininet
	"""

	def __init__(self, ft_topo):

		Topo.__init__(self)
		self.ft_topo=ft_topo
		self.switch_id_to_ip={}
		self.switches_routing_tables={}
		self.connections= set()
		
		self.all_nodes={}

		# TODO: please complete the network generation logic here

		#add core level switches to mininet
		for core_s in ft_topo.switches[0]:
			self.add_node_to_flat_graph(core_s)
			self.addSwitch(core_s.unique_id, cls=OVSKernelSwitch)
			self.switch_id_to_ip[core_s.unique_id]=core_s.ip
			self.add_connections(core_s)
        	
		for pod_id in range(ft_topo.pods_count):
        
			#adding aggregate level switches to mininet
			for aggregate_s in ft_topo.switches[1][pod_id]:
				self.add_node_to_flat_graph(aggregate_s)
				self.addSwitch(aggregate_s.unique_id, cls=OVSKernelSwitch)
				self.switch_id_to_ip[aggregate_s.unique_id]=aggregate_s.ip
				self.add_connections(aggregate_s)
				
			
			#adding edge level switches to mininet
			for edge_s in ft_topo.switches[2][pod_id]:
				self.add_node_to_flat_graph(edge_s)
				self.addSwitch(edge_s.unique_id, cls=OVSKernelSwitch)
				self.switch_id_to_ip[edge_s.unique_id]=edge_s.ip
				self.add_connections(edge_s)
				
			#adding servers to mininet
			for server in ft_topo.servers[0][pod_id]:
				self.add_node_to_flat_graph(server)
				self.addHost(server.unique_id,ip=server.ip)
				self.add_connections(server)
        		

		#generate connections
		for source, destination in self.connections:
			self.addLink(source,destination,cls=TCLink,bw=15,delay=5)
		
		self.genrate_core_switch_forwarding_table();


	def add_connections(self,node):				
		for edge in node.edges:
			self.connections.add(( edge.lnode.unique_id, edge.rnode.unique_id ))
	
	def add_node_to_flat_graph(self, node):
				
		self.all_nodes.setdefault(node.unique_id,[])
		neighbours = set()
		
		for edge in node.edges:
			if edge.rnode.unique_id not in self.all_nodes[node.unique_id] and node.unique_id != edge.rnode.unique_id:
				neighbours.add(edge.rnode.unique_id)
			elif edge.lnode.unique_id not in self.all_nodes[node.unique_id] and node.unique_id != edge.lnode.unique_id:
				neighbours.add(edge.lnode.unique_id)			
			
		self.all_nodes[node.unique_id]=list(neighbours)
			
	
	def genrate_core_switch_forwarding_table(self):
		
		for j in range(1, (self.ft_topo.number_of_ports // 2) + 1):
			for i in range(1, (self.ft_topo.number_of_ports // 2) + 1):
				for pod_id in range(0,self.ft_topo.number_of_ports):
					core_switch=self.ft_topo.switches[0][pod_id]
					self.add_prefix(core_switch.unique_id, f"10.{pod_id}.0.0",pod_id)
		
		
	
	def add_prefix(self,switch_id,destination_ip,out_port):
		self.switches_routing_tables.setdefault(switch_id,{})
		self.switches_routing_tables[switch_id][destination_ip]=out_port
		
		
		
		     


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()


if __name__ == '__main__':
    ft_topo = Fattree(4)
    net_topo = FattreeNet(ft_topo)
    dijkstra_algo = Dijkistra(net_topo.all_nodes,"pserver11","pserver30")
    #run(ft_topo)
