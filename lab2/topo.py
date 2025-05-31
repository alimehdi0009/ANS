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

from enum import Enum
 

# Class for an edge in the graph
class Edge:
	def __init__(self):
		self.lnode = None
		self.rnode = None
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False

class TopologyLevel(Enum):
	CORE = 'core'
	AGGREGATE = 'aggregate'
	EDGE = 'edge'


class Fattree:

	def __init__(self, num_ports):
	
		""" 
		Servers list structure: 
		[
			{'core level' : [list if switches in the core level]}, => 0th index in the serves list
			{'aggregate level' : {'pod_id':[list of aggregate switches in that pod]} }, => 1st index in the servers list
			{'edge level':{'pod_id':[list of edge switches in that pod]} }, => 2nd index in the servers list
		]
			
		"""
		self.servers = []
		self.switches = []
		
		
		
		self.pods_count = num_ports
		self.core_switches_count = (num_ports // 2) ** 2
		self.aggregation_switches_count = (num_ports ** 2) // 2
		self.edge_switches_count = (num_ports ** 2) // 2
		self.total_servers_count = (num_ports ** 3) // 4
		
		self.aggre_switches_per_pod = num_ports // 2
		self.edge_switches_per_pod = num_ports // 2
		self.servers_per_switch = num_ports // 2
		self.group_size = num_ports // 2
		
		
		print(f"""
Pods Count: {self.pods_count}
Core Switches Count: {self.core_switches_count}
Aggregation Switches Count: {self.aggregation_switches_count}
Edge Switches Count: {self.edge_switches_count}
Total Servers Count: {self.total_servers_count}

Aggregation Switches per Pod: {self.aggre_switches_per_pod}
Edge Switches per Pod: {self.edge_switches_per_pod}
Servers per Switch: {self.servers_per_switch}
Group Size: {self.group_size}
""")

		
		#list for core switches
		self.switches.append([])
		
		#dictionary for aggregate switches
		self.switches.append({})
		
		#dictionary for edge switches
		self.switches.append({})
		
		self.generate(num_ports)
		self.iterate_topology()
		
	def generate_core_swicthes(self):
	
		self.switches.append([])
		
		for switch_id in range(self.core_switches_count):
			name = f"core_s{switch_id}"
			new_switch = Node(switch_id,name)
			self.switches[0].append(new_switch)
			
	def generate_pod_aggregate_swicthes(self,pod_id):
		
		self.switches[1].setdefault(pod_id,[])
		
		for switch_id in range(self.aggre_switches_per_pod):
			name = f"p{pod_id}_aggr_s{switch_id}"
			new_switch = Node(switch_id,name)
			self.switches[1][pod_id].append(new_switch)
			
	
	
	def generate_pod_edge_switches(self,pod_id):
		
		self.switches[2].setdefault(pod_id,[])
		
		for switch_id in range(self.edge_switches_per_pod):
			name = f"p{pod_id}_edge_s{switch_id}"
			new_switch = Node(switch_id,name)
			self.switches[2][pod_id].append(new_switch)
			
			self.generate_servers_for_edge_switch(new_switch)
	
	def generate_servers_for_edge_switch(self,switch):
		for server_id in range(self.servers_per_switch):
			new_server = Node(server_id,f"server{server_id}")
			self.servers.append(new_server)
			
			switch.add_edge(new_server)
			
	def connect_pod_aggregate_edge_switches(self,pod_id):
		
		for agg_switch in self.switches[1][pod_id]:
			for edge_switch in self.switches[2][pod_id]:
				agg_switch.add_edge(edge_switch)
	
	def get_core_switches_for_aggregation(self,aggr_switch_index):
		return [(aggr_switch_index * self.group_size) + j for j in range(self.group_size) ]
	
	
	def connect_core_aggregate_switches(self):
	
		for pod_id in range(self.pods_count):
			for aggre_switch in self.switches[1][pod_id]:
			
				core_indices = self.get_core_switches_for_aggregation(aggre_switch.id)				
				for core_index in core_indices:
					self.switches[0][core_index].add_edge(aggre_switch)
		
	

	def generate(self, num_ports):

		# TODO: code for generating the fat-tree topology
		
		#generate the core switches
		self.generate_core_swicthes()
		
		#generate aggregate and edge switches for the pods
		for pod_id in range(self.pods_count):
			
			#generate pod aggregate switches
			self.generate_pod_aggregate_swicthes(pod_id)
						
			#generate pod edge switches
			self.generate_pod_edge_switches(pod_id)
			
			#connect aggregate switches to edge swicthes
			self.connect_pod_aggregate_edge_switches(pod_id)
									
		#connecting core switches with aggregate
		self.connect_core_aggregate_switches();
		
	
	def iterate_edges(self,node):
		
		for edge in node.edges:
			print(f"Switch type: {edge.rnode.type} | Switch id: {edge.rnode.id}")
			
			
	def iterate_topology(self):
	
		
		for core_switch in self.switches[0]:
			print(f"Switch type: {core_switch.type} | Switch id: {core_switch.id}")
			
			print('connections:')
			
			self.iterate_edges(core_switch)
			print("--------------------------------------------------------------")
		
		for pod_id in range(self.pods_count):
		
			print(f"Iterating Pod id: {pod_id} aggregate switches")
			
			for aggregate_switch in self.switches[1][pod_id]:
				print(f"Switch type: {aggregate_switch.type} | Switch id: {aggregate_switch.id}")
				
				print("connections:")
				
				self.iterate_edges(aggregate_switch)
				print("--------------------------------------------------------------")
				
			
			print(f"Iterating Pod id: {pod_id} edge switches")
			
			for edge_switch in self.switches[2][pod_id]:
				print(f"Switch type: {edge_switch.type} | Switch id: {edge_switch.id}")
				
				print("connections:")
				
				self.iterate_edges(edge_switch)
				print("--------------------------------------------------------------")
				
				
if __name__ == "__main__":
	fat_tree = Fattree(4)
		
				
				
				
			
			
			
		
		
		
		
		
		
		
		
