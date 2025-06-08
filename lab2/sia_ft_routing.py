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

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, ipv4, ether_types, arp, icmp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo

from ryu.lib import hub


class FTRouter(app_manager.RyuApp):
	
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
	
	def __init__(self, *args, **kwargs):
		super(FTRouter, self).__init__(*args, **kwargs)
		
		self.k=4
		# Initialize the topology with #ports=4
		
		self.datapath_to_ip={}
		self.switch_possible_ports=list(range(1, self.k+1))
		self.datapath_port_to_connected_ip={}
		self.datapath_ports={}
		self.datapath_to_ports={}
		
		self.topo_net = topo.Fattree(self.k)
		self.core_routing_table={}
		
		self.discovery_done = False
		self.discovery_thread = hub.spawn(self.get_topology_data)
		
		self.pod_switches_routing_tables={}
		
		self.pod_switches_routing_tables.setdefault("aggregate",{})
		self.pod_switches_routing_tables.setdefault("edge",{})
		
		self.switch_mac_to_port={}
		
		self.generate_datapath_to_ip(self.topo_net)
		
		self.ip_to_datapath={ ip: dp for dp, ip in self.datapath_to_ip.items()}
		
		self.generate_core_switch_routing_table()
		
		self.generate_aggregate_switches_routing_tables()
		
		self.generate_edge_switches_routing_tables()
		
	# Topology discovery
	#@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev=None):
		expected_switches = int((5 * self.k * self.k) / 4)
		expected_links = int((3 * self.k * self.k * self.k) / 4)

		while not self.discovery_done:
			switches = get_switch(self, None)
			links = get_link(self, None)

			if len(switches) < expected_switches or len(links) < expected_links:
				print(f"Waiting for topology... ({len(switches)}/{expected_switches} switches, "
					  f"{len(links)}/{expected_links} links)")
				hub.sleep(2)
				continue

			print(f"Topology discovery finished. Found all {expected_switches} switches and {expected_links} links.")

			for sw in switches:
				dp = sw.dp
				self.switch_mac_to_port.setdefault(dp.id, {})
				for port in sw.ports:
					if port.hw_addr not in self.switch_mac_to_port[dp.id]:
						self.switch_mac_to_port[dp.id][port.hw_addr] = port.port_no

			for link in links:
				src = link.src
				dst = link.dst

				src_ip = self.datapath_to_ip.get(src.dpid)
				dst_ip = self.datapath_to_ip.get(dst.dpid)

				if not src_ip or not dst_ip:
					continue  # Skip if mapping is incomplete

				self.datapath_port_to_connected_ip.setdefault(src_ip, {})
				self.datapath_port_to_connected_ip.setdefault(dst_ip, {})

				self.datapath_to_ports.setdefault(src_ip, [])
				self.datapath_to_ports.setdefault(dst_ip, [])

				if dst_ip not in self.datapath_port_to_connected_ip[src_ip]:
					self.datapath_port_to_connected_ip[src_ip][dst_ip] = src.port_no
				if src.port_no not in self.datapath_to_ports[src_ip]:
					self.datapath_to_ports[src_ip].append(src.port_no)

				if src_ip not in self.datapath_port_to_connected_ip[dst_ip]:
					self.datapath_port_to_connected_ip[dst_ip][src_ip] = dst.port_no
				if dst.port_no not in self.datapath_to_ports[dst_ip]:
					self.datapath_to_ports[dst_ip].append(dst.port_no)

			# Once topology is discovered, generate the routing tables
			self.configure_core_forwarding_table()
			self.configure_aggregate_switches_forwarding_tables()
			self.configure_edge_switches_forwarding_tables()

			self.discovery_done = True

	def configure_core_forwarding_table(self):
	
	
		#configuring the core switches routing table
		for core_switch_ip in self.core_routing_table:
		
			if core_switch_ip not in self.datapath_port_to_connected_ip:
				continue
			
			core_switch_routing_entries = self.core_routing_table[core_switch_ip]
			
			core_connections=self.datapath_port_to_connected_ip[core_switch_ip]
			
			for connected_ip in core_connections:
				switch_first_two_octates= ".".join(connected_ip.split(".")[:2])
				
				for core_routing_entry in core_switch_routing_entries:
					if core_routing_entry.startswith(switch_first_two_octates):
						
						self.core_routing_table[core_switch_ip][core_routing_entry]=core_connections[connected_ip]
		
	def configure_aggregate_switches_forwarding_tables(self):
		#configuring the core switches prefix and suffix routing table
		for pod_switch_ip in self.pod_switches_routing_tables["aggregate"]:
			
			if pod_switch_ip not in self.datapath_port_to_connected_ip or pod_switch_ip not in self.pod_switches_routing_tables["aggregate"]:
				print(f"not discovered..!{pod_switch_ip}")
				continue
				
			pod_switch_prefix_routing_entries  = self.pod_switches_routing_tables["aggregate"][pod_switch_ip]["prefix"]			
			
			pod_switch_connections=self.datapath_port_to_connected_ip[pod_switch_ip]
			
			common_entries = { ip: out_port for ip, out_port in pod_switch_connections.items() if ip in pod_switch_prefix_routing_entries }
			
			uncommen_entries = { ip: out_port for ip, out_port in pod_switch_connections.items() if ip not in pod_switch_prefix_routing_entries }

			#configuring prefix
			for connected_ip in common_entries:
			
				switch_ip_first_three_octates = ".".join(connected_ip.split(".")[:3])
				
				for pod_switch_prefix_routing_entry in pod_switch_prefix_routing_entries:
									
					if pod_switch_prefix_routing_entry == connected_ip or pod_switch_prefix_routing_entry.startswith(switch_ip_first_three_octates):
						
						self.pod_switches_routing_tables["aggregate"][pod_switch_ip]["prefix"][pod_switch_prefix_routing_entry]=pod_switch_connections[connected_ip]
								
			#configuring suffix
			
			pod_switch_suffix_routing_entries  = self.pod_switches_routing_tables["aggregate"][pod_switch_ip]["suffix"]
			
			pod_switch_suffix_zipped_entries=dict(zip(pod_switch_suffix_routing_entries.keys(), uncommen_entries.values()))
			
			self.pod_switches_routing_tables["aggregate"][pod_switch_ip]["suffix"]=pod_switch_suffix_zipped_entries
		
		


	def configure_edge_switches_forwarding_tables(self):
		#configuring the core switches prefix and suffix routing table
		for pod_switch_ip in self.pod_switches_routing_tables["edge"]:
			
			if pod_switch_ip not in self.datapath_port_to_connected_ip or pod_switch_ip not in self.pod_switches_routing_tables["edge"]:
				print(f"not discovered..!{pod_switch_ip}")
				continue
				
			pod_switch_prefix_routing_entries  = self.pod_switches_routing_tables["edge"][pod_switch_ip]["prefix"]			
			
			pod_switch_connections=self.datapath_port_to_connected_ip[pod_switch_ip]
			
			common_entries = { ip: out_port for ip, out_port in pod_switch_connections.items() if ip in pod_switch_prefix_routing_entries }
			
			uncommen_entries = { ip: out_port for ip, out_port in pod_switch_connections.items() if ip not in pod_switch_prefix_routing_entries }
			
			
			discovered_port_for_aggregate =list(pod_switch_connections.values())
			pod_switch_suffix_routing_entries  = self.pod_switches_routing_tables["edge"][pod_switch_ip]["suffix"]
			
			missing_ports = list(set(self.switch_possible_ports) - set(discovered_port_for_aggregate))
			
			pod_switchzipped_routing_entries=dict(zip(pod_switch_suffix_routing_entries.keys(),discovered_port_for_aggregate))
						
			self.pod_switches_routing_tables["edge"][pod_switch_ip]["suffix"]=pod_switchzipped_routing_entries

			
						 
	
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
	
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# Install entry-miss flow entry
		match = parser.OFPMatch()
		
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		
		self.add_flow(datapath, 0, match, actions)
	
	# Add a flow entry to the flow-table
	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# Construct flow_mod message and send it
		
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
		
		datapath.send_msg(mod)
	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		dpid = datapath.id
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# TODO: handle new packets at the controller
		
		in_port = msg.match['in_port']
		
		received_packet = packet.Packet(msg.data)
		
		eth_pkt = received_packet.get_protocol(ethernet.ethernet)
		
		src_ip = None
		dst_ip = None
		
		src_mac=eth_pkt.src
		dst_mac=eth_pkt.dst
		
		if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
		
			arp_pkt = received_packet.get_protocol(arp.arp)
		
			arp_header = received_packet.get_protocol(arp.arp)
			src_ip=arp_header.src_ip
			dst_ip=arp_header.dst_ip
			
			src_mac=arp_header.src_mac
			dst_mac=arp_header.dst_mac
			
		elif eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
		
			ipv4_header = received_packet.get_protocol(ipv4.ipv4)
			src_ip=ipv4_header.src
			dst_ip=ipv4_header.dst


		current_datapath_ip=self.datapath_to_ip[dpid]
	
		if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP or eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
			
			self.switch_mac_to_port.setdefault(dpid,{})	
				
			if src_mac not in self.switch_mac_to_port[dpid]:
				self.switch_mac_to_port[dpid][src_mac]=in_port
			
			if current_datapath_ip not in self.datapath_port_to_connected_ip:
				self.datapath_port_to_connected_ip.setdefault(current_datapath_ip,{})
				
			if current_datapath_ip in self.pod_switches_routing_tables["edge"] and src_ip in self.pod_switches_routing_tables["edge"][current_datapath_ip]["prefix"]:
				self.pod_switches_routing_tables["edge"][current_datapath_ip]["prefix"][src_ip]=in_port
			
			if current_datapath_ip not in self.datapath_to_ports:
				self.datapath_to_ports.setdefault(current_datapath_ip,[])
			
			if in_port not in self.datapath_to_ports[current_datapath_ip]:
				self.datapath_to_ports[current_datapath_ip].append(in_port)
			
			
			datapath_prefix_forwarding_table = None
			datapath_suffix_forwarding_table = None
			
			out_port=None
			priority=1
			
			#if packet is at the edge switch then it check edge forwarding table
			if current_datapath_ip in self.pod_switches_routing_tables["edge"]:
				datapath_prefix_forwarding_table = self.pod_switches_routing_tables["edge"][current_datapath_ip]["prefix"]
				datapath_suffix_forwarding_table = self.pod_switches_routing_tables["edge"][current_datapath_ip]["suffix"]
				
			
			#if packet is at the aggregate switch then check aggregate forwarding table
			elif current_datapath_ip in self.pod_switches_routing_tables["aggregate"]:
				datapath_prefix_forwarding_table = self.pod_switches_routing_tables["aggregate"][current_datapath_ip]["prefix"]
				datapath_suffix_forwarding_table = self.pod_switches_routing_tables["aggregate"][current_datapath_ip]["suffix"]
			
			
			current_datapath_network_prefix_24 = ".".join(current_datapath_ip.split(".")[:3]) # /24 of current datapath ip
			
			dst_ip_nextwork_prefix_24 = ".".join(dst_ip.split(".")[:3]) # get /24 of the dst ip for pod switch prefix match
			
			dst_ip_host_byte = dst_ip.split(".")[3] # get host byte from dst ip for the suffix match
			
			dst_ip_nextwork_prefix_16 = ".".join(dst_ip.split(".")[:2]) #get /16 from dst ip for the prefix match at core switch 
			
			#if there is a terminating entry in the prefix table on the switch then forward the packet to the port
			
			if datapath_prefix_forwarding_table and dst_ip in datapath_prefix_forwarding_table and datapath_prefix_forwarding_table[dst_ip] is not None:
				out_port = datapath_prefix_forwarding_table[dst_ip]
				priority=5
			elif dst_ip in self.datapath_port_to_connected_ip[current_datapath_ip]:
				out_port=self.datapath_port_to_connected_ip[current_datapath_ip][dst_ip]
				priority=5
			elif current_datapath_network_prefix_24 == dst_ip_nextwork_prefix_24: # current datapath /24 and dst ip /24 matched means same subnet(at the desired edge switch)
				
				existing_datapath_ports=self.datapath_to_ports[current_datapath_ip]
				
				missing_ports = list(set(self.switch_possible_ports) - set(existing_datapath_ports))
				
				for out_port in missing_ports:
					actions = [parser.OFPActionOutput(out_port)]
					packet_out = parser.OFPPacketOut(
									datapath=datapath,
									buffer_id=msg.buffer_id,
									in_port=in_port,
									actions=actions,
									data=msg.data)
					datapath.send_msg(packet_out)
				out_port=None
				
					
				
			elif datapath_prefix_forwarding_table:	
				#checking in the prefix table based on the /24 prefix match. following line return a matching values tuple (ip,port) if exists else None
				prefix_matching_entry = next(((ip, port) for ip, port in datapath_prefix_forwarding_table.items() if ip.startswith(dst_ip_nextwork_prefix_24) and port is not None), None)
				
				if prefix_matching_entry is not None:
					out_port = prefix_matching_entry[1]
					priority=2
				else:
					#checking in the prefix table based on the /8 suffix match
					suffix_matching_entry = next(((ip, port) for ip, port in datapath_suffix_forwarding_table.items() if ip.endswith(dst_ip_host_byte) and port is not None), None)
					
					if suffix_matching_entry is not None:
						out_port = suffix_matching_entry[1]
						priority=2
					
			#at this point if outport is still None it means we are at the core switch and need /16 prefix match
			if out_port is None and current_datapath_ip in self.core_routing_table:
				#performing /16 prefix match at core roting table entires
				core_table_matching_entry = next(((ip, port) for ip, port in self.core_routing_table[current_datapath_ip].items() if ip.startswith(dst_ip_nextwork_prefix_16)), None)
				
				if core_table_matching_entry is not None:
					out_port = core_table_matching_entry[1]
					priority=2
			
			#at this point if port is not found it mean something is not fine
			if out_port is None:
				return
			else:
				
				actions = [parser.OFPActionOutput(out_port)]
				
				match = parser.OFPMatch(in_port=in_port, ipv4_src = src_ip, ipv4_dst = dst_ip, eth_type=0x0800)
				self.add_flow(datapath, priority, match,actions)
				packet_out = parser.OFPPacketOut(
								datapath=datapath,
								buffer_id=msg.buffer_id,
								in_port=in_port,
								actions=actions,
								data=msg.data)
				datapath.send_msg(packet_out)
				
					
		
	def generate_datapath_to_ip(self,ft_topo):
	
		#add core level switches to mininet
		for core_s in ft_topo.switches[0]:
			self.datapath_to_ip[int(core_s.unique_id.split("-")[1])]=core_s.ip
        	
		for pod_id in range(ft_topo.pods_count):
        
			#adding aggregate level switches to mininet
			for aggregate_s in ft_topo.switches[1][pod_id]:
				self.datapath_to_ip[int(aggregate_s.unique_id.split("-")[1])]=aggregate_s.ip
				
			
			#adding edge level switches to mininet
			for edge_s in ft_topo.switches[2][pod_id]:
				self.datapath_to_ip[int(edge_s.unique_id.split("-")[1])]=edge_s.ip
		

	def generate_core_switch_routing_table(self):
		

		for j in list(range(1,(self.k//2)+1)):
			for i in list(range(1,(self.k//2)+1)):
				for pod in list(range(0,self.k)):
					self.core_routing_table.setdefault(f"10.{self.k}.{j}.{i}",{})
					self.core_routing_table[f"10.{self.k}.{j}.{i}"][f"10.{pod}.0.0"]=None
	
	
	
	def generate_aggregate_switches_routing_tables(self):
	

		for pod in range(0,self.k):
			for switch in range(self.k//2, self.k):			
				for subnet in range(0,self.k//2):
					self.pod_switches_routing_tables["aggregate"].setdefault(f"10.{pod}.{switch}.1",{})
					self.pod_switches_routing_tables["aggregate"][f"10.{pod}.{switch}.1"].setdefault("prefix",{})
					self.pod_switches_routing_tables["aggregate"][f"10.{pod}.{switch}.1"]["prefix"][f"10.{pod}.{subnet}.1"]=None
										
				self.pod_switches_routing_tables["aggregate"][f"10.{pod}.{switch}.1"]["prefix"][f"0.0.0.0"]=None
				
				for host in range(2, (self.k//2)+2):
					self.pod_switches_routing_tables["aggregate"].setdefault(f"10.{pod}.{switch}.1",{})
					self.pod_switches_routing_tables["aggregate"][f"10.{pod}.{switch}.1"].setdefault("suffix",{})
					self.pod_switches_routing_tables["aggregate"][f"10.{pod}.{switch}.1"]["suffix"][f"10.0.0.{host}"]=None
					
	def generate_edge_switches_routing_tables(self):
	
		for pod in range(0,self.k):
			for switch in range(0,self.k//2):
				for host in range(2, (self.k//2) +2):
					
					self.pod_switches_routing_tables["edge"].setdefault(f"10.{pod}.{switch}.1",{})
					self.pod_switches_routing_tables["edge"][f"10.{pod}.{switch}.1"].setdefault("prefix",{})
					self.pod_switches_routing_tables["edge"][f"10.{pod}.{switch}.1"]["prefix"][f"10.{pod}.{switch}.{host}"]=None
				
				self.pod_switches_routing_tables["edge"][f"10.{pod}.{switch}.1"]["prefix"][f"0.0.0.0"]=None
			
				for host in range(2, (self.k//2)+2):
					self.pod_switches_routing_tables["edge"].setdefault(f"10.{pod}.{switch}.1",{})
					self.pod_switches_routing_tables["edge"][f"10.{pod}.{switch}.1"].setdefault("suffix",{})
				
					self.pod_switches_routing_tables["edge"][f"10.{pod}.{switch}.1"]["suffix"][f"10.0.0.{host}"]=None
				
