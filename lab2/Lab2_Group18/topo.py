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
	def __init__(self, id, type, unique_id, ip=None):
		self.edges = []
		self.id = id
		self.type = type
		self.unique_id = unique_id
		self.ip=ip

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
		
		self.datapath_flat_graph={}
		
		self.ip_flat_graph={}
		
		self.number_of_ports=num_ports
		self.pods_count = num_ports
		self.core_switches_count = (num_ports // 2) ** 2
		self.aggregation_switches_count = (num_ports ** 2) // 2
		self.edge_switches_count = (num_ports ** 2) // 2
		self.total_servers_count = (num_ports ** 3) // 4
		
		self.aggre_switches_per_pod = num_ports // 2
		self.edge_switches_per_pod = num_ports // 2
		self.servers_per_switch = num_ports // 2
		self.servers_per_pod = (num_ports ** 2) // 4
		self.group_size = num_ports // 2
	
		self.node_types = {
			"core": 1,
			"aggregation": 2,
			"edge": 3,
			"server": 4
			}
		
		#list for core switches
		self.switches.append([])
		
		#dictionary for aggregate switches
		self.switches.append({})
		
		#dictionary for edge switches
		self.switches.append({})
		
		#dictionary for edge servers
		self.servers.append({})
		
		
		self.generate(num_ports)
		self.generate_flat_tree()
	
	#For the core switches we use 10.k.j.i pattern to generate the ip addresses
	#Where values of the j and i are the core switch cooredinates in the (k//2) ** 2 core switch grid and i, and j belongs to [1, k/2]
	#For k=4 i,j belongs to [1,2]. The grid is from top left 
	#assigning ip addresses based on the paper
	def generate_core_swicthes(self):
	
		self.switches.append([])
		
		for j in range(self.group_size):
			for i in range(self.group_size):
				switch_id = (j * self.group_size) + i
				ip = f"10.{self.number_of_ports}.{j+1}.{i+1}"
				switch_type = "core"
				uid=f"core-{self.make_unique_id('core',0,switch_id)}"
				new_switch = Node(switch_id,switch_type,uid,ip)
				self.switches[0].append(new_switch)
	
	#for the pod switches we use 10.pod.switch.1 for the ip address
	#where pod is the pod number and switch is the switch number from left to right and botton to top
	#in out topology for aggregation the switch value for the ip is calculated as (switch_id + (num_ports/2))	
	def generate_pod_aggregate_swicthes(self,pod_id):
		
		self.switches[1].setdefault(pod_id,[])
		
		for switch_id in range(self.aggre_switches_per_pod):
			type = "aggregation"
			uid=f"aggr-{self.make_unique_id('aggregation',pod_id,switch_id)}"
			ip = f"10.{pod_id}.{switch_id + self.group_size}.1"
			new_switch = Node(switch_id,type,uid,ip)
			self.switches[1][pod_id].append(new_switch)
			
	
	#for the pod switches we use 10.pod.switch.1 for the ip address
	#where pod is the pod number and switch is the switch number from left to right and botton to top
	#in out topology for aggregation the switch value for the ip is calculated as (switch_id + (num_ports/2))
	def generate_pod_edge_switches(self,pod_id):
		
		self.switches[2].setdefault(pod_id,[])
				
		for switch_id in range(self.edge_switches_per_pod):
			type="edge"
			uid = f"edge-{self.make_unique_id('edge',pod_id,switch_id)}"
			ip = f"10.{pod_id}.{switch_id}.1"
			new_switch = Node(switch_id,type,uid,ip)
			self.switches[2][pod_id].append(new_switch)
			
			self.generate_servers_for_edge_switch(pod_id,new_switch)
	
	
	#server has ip addresses of 10.pod.switch.ID pattern where ID is the host position in the subnet and is ranged from [2,(k/2)+1].
	#this is to protect the ip conflicts from switches in the upper levels
	def generate_servers_for_edge_switch(self,pod_id,switch):
		
		self.servers[0].setdefault(pod_id,[])
		for server_id in range(self.servers_per_switch):
			uid=f"ser-{self.make_unique_id('server',pod_id,switch.id,server_id)}"
			type="server"
			ip=f"10.{pod_id}.{switch.id}.{server_id+2}"
			new_server = Node(server_id,type,uid,ip)
			self.servers[0][pod_id].append(new_server)
			
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
		
	def make_unique_id(self,node_type, pod_id, node_id, server_id=0):
		if node_type == 'server':
			return f"{ self.node_types[node_type]}{pod_id}{node_id}{server_id}"
		else:
			return f"{ self.node_types[node_type]}{pod_id}{node_id}"

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

	def generate_flat_tree(self):
	
		for core_s in self.switches[0]:
			self.add_node_to_datapath_flat_graph(core_s)
			self.add_node_to_ip_flat_graph(core_s)
			
		for pod_id in range(self.pods_count):
        
			#adding aggregate level switches to mininet
			for aggregate_s in self.switches[1][pod_id]:
				self.add_node_to_datapath_flat_graph(aggregate_s)
				self.add_node_to_ip_flat_graph(aggregate_s)
				
			
			#adding edge level switches to mininet
			for edge_s in self.switches[2][pod_id]:
				self.add_node_to_datapath_flat_graph(edge_s)
				self.add_node_to_ip_flat_graph(edge_s)
				
			#adding servers to mininet
			for server in self.servers[0][pod_id]:
				self.add_node_to_datapath_flat_graph(server)
				self.add_node_to_ip_flat_graph(server)
				
	def add_node_to_datapath_flat_graph(self, node):
		
		node_dpid=self.get_datapath_id(node)

		self.datapath_flat_graph.setdefault(node_dpid,[])
		
		neighbours = set()
		
		for edge in node.edges:
			
			rnode_dpid=self.get_datapath_id(edge.rnode)
			lnode_dpid=self.get_datapath_id(edge.lnode)
			
			if rnode_dpid not in self.datapath_flat_graph[node_dpid] and node_dpid != rnode_dpid: #ignore edge nodes that point to itself
				neighbours.add(rnode_dpid)
			elif lnode_dpid not in self.datapath_flat_graph[node_dpid] and node_dpid != lnode_dpid:
				neighbours.add(lnode_dpid)			
			
		self.datapath_flat_graph[node_dpid]=list(neighbours)
		
	
	def add_node_to_ip_flat_graph(self, node):
		
		self.ip_flat_graph.setdefault(node.ip,[])
		
		neighbours = set()
		
		for edge in node.edges:
			if edge.rnode.ip not in self.ip_flat_graph[node.ip] and node.ip != edge.rnode.ip: #ignore edge nodes that point to itself
				neighbours.add(edge.rnode.ip)
			elif edge.lnode.ip not in self.ip_flat_graph[node.ip] and node.ip != edge.lnode.ip:
				neighbours.add(edge.lnode.ip)			
			
		self.ip_flat_graph[node.ip]=list(neighbours)
				

	def get_datapath_id(self,node):
		
		return int(node.unique_id.split("-")[1])
		
#if __name__ == "__main__":
#	fat_tree = Fattree(4)
		
				
				
				
			
			
			
		
		
		
		
		
		
		
		
