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


class Fattree:

	def __init__(self, num_ports):
		self.servers = []
		self.switches = []
		
		
		
		self.pods_count = num_ports
		self.core_switches_count = (num_ports // 2) ** 2
		self.aggregation_switches_count = (num_ports ** 2) // 2
		self.edge_switches_count = (num_ports ** 2) // 2
		self.total_servers_count = (num_ports ** 3) // 4
		
		self.aggre_switches_per_pod = num_ports ** 2
		self.edge_switches_per_pod = num_ports ** 2
		self.servers_per_switch = num_ports ** 2
		
		self.generate(num_ports)

	def generate(self, num_ports):

		# TODO: code for generating the fat-tree topology
		
		#generate the core switches
		self.switches.append({'core':[]})
		
		for switch_id in range(self.core_switches_count):
			new_switch = Node(switch_id,'core')
			
			self.switches[0]['core'].append(new_switch)
			
		
		for pod_id in range(self.pods_count):
			
			#generate pod aggregate switches
			self.switches.append({'aggregate':{}})
			for switch_id in range(self.aggre_switches_per_pod):
				new_switch = Node(switch_id,'aggregate')
			
				self.switches[1]['aggregate'].setdefault({pod_id:[]}).append(new_switch)
			
			
			#generate pod edge switches
			self.switches.append({'edge':{}})
			for switch_id in range(self.edge_switches_per_pod):
			
				new_switch = Node(switch_id,'edge')
				self.switches[1]['edge'].setdefault({pod_id:[]}).append(new_switch)
				
				#generate the servers for switch in the pod
				for server_id in range(self.servers_per_switch):
				
					new_server = Node(server_id,'server')
					new_server.add_edge(new_switch)
					
					self.servers.append(new_server)
			
			#connect aggregate switches to edge swicthes
			for agg_switch in self.switches[0]['aggregate'][pod_id]:
			
				for edge_switch in self.swicthes[1]['edge'][pod_id]:
					
					agg_switch.add_edge(edge_switch)
					
			
							
		
		for core_switch in self.switchs[0]['core']:
			
			for pod_id in range(self.pods_count):
				
				#getting index of the aggregate switch to connect the core switch with
				aggregate_switch_index = core_switch.id % self.edge_switches_per_pod;
				
				#getting aggregate switch based on the calculated index 
				aggregate_switch_to_connect_with = self.server[1]['aggregate'][pod_id][aggregate_switch_index]
				
				#connecting core with reterived aggregate switch
				core_switch.add_edge(aggregate_switch_to_connect_with)
				
				
				
			
			
			
		
		
		
		
		
		
		
		
