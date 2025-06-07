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
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo


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
		
		self.pod_switches_routing_tables={}
		
		self.switch_mac_to_port={}
		
		self.generate_datapath_to_ip(self.topo_net)
		
		self.ip_to_datapath={ ip: dp for dp, ip in self.datapath_to_ip.items()}
		
		self.generate_core_switch_routing_table()
		
		self.generate_pod_switches_routing_tables()
		
		print(len(self.pod_switches_routing_tables["prefix"]))
		
		print(self.datapath_port_to_connected_ip)
	
	# Topology discovery
	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
	
		# Switches and links in the network
		switches = get_switch(self, None)
		links = get_link(self, None)
		

		for sw in switches:
			
			dp=sw.dp		
			self.switch_mac_to_port.setdefault(dp.id,{})	
				
			for port in sw.ports:			
				if port.hw_addr not in self.switch_mac_to_port[dp.id]:
					self.switch_mac_to_port[dp.id][port.hw_addr]=port.port_no
		
		for link in links:
			src=link.src
			dst=link.dst
			
			src_dp_ip = self.datapath_to_ip[src.dpid]
			dst_dp_ip = self.datapath_to_ip[dst.dpid]
			
			self.datapath_port_to_connected_ip.setdefault(src_dp_ip,{})
			self.datapath_port_to_connected_ip.setdefault(dst_dp_ip,{})
			
			self.datapath_to_ports.setdefault(src_dp_ip,[])
			self.datapath_to_ports.setdefault(dst_dp_ip,[])
			
			if src.port_no not in self.datapath_port_to_connected_ip[src_dp_ip]:
				dst_ip=self.datapath_to_ip[dst.dpid]
				
				self.datapath_port_to_connected_ip[src_dp_ip][dst_ip]=src.port_no
				
			if src.port_no not in self.datapath_to_ports[src_dp_ip]:
				self.datapath_to_ports[src_dp_ip].append(src.port_no)
				
			if dst.port_no not in self.datapath_port_to_connected_ip[dst_dp_ip]:
				src_ip=self.datapath_to_ip[src.dpid]
				self.datapath_port_to_connected_ip[dst_dp_ip][src_ip]=dst.port_no
			
			if dst.port_no not in self.datapath_to_ports[dst_dp_ip]:
				self.datapath_to_ports[dst_dp_ip].append(dst.port_no)
			
		
		#configuring the core switches routing table
		for core_switch_ip in self.core_routing_table:
			
			if core_switch_ip not in self.datapath_port_to_connected_ip:
				continue
			
			core_switch_routing_entries = self.core_routing_table[core_switch_ip]
			
			core_connections=self.datapath_port_to_connected_ip[core_switch_ip]
			
			for conn in core_connections:
				switch_first_two_octates= ".".join(conn.split(".")[:2])
				
				for routing_entry in core_switch_routing_entries:
					
					if routing_entry.startswith(switch_first_two_octates):
						self.core_routing_table[core_switch_ip][routing_entry]=self.datapath_port_to_connected_ip[core_switch_ip][conn]
	
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
	
	
	
	def generate_pod_switches_routing_tables(self):
	
		self.pod_switches_routing_tables.setdefault("prefix",{})
		self.pod_switches_routing_tables.setdefault("suffix",{})
		
		for pod in range(0,self.k):
			for switch in range(self.k//2, self.k):			
				for subnet in range(0,self.k//2):
				
					self.pod_switches_routing_tables["prefix"].setdefault(f"10.{pod}.{switch}.1",{})
					self.pod_switches_routing_tables["prefix"][f"10.{pod}.{switch}.1"][f"10.{pod}.{subnet}.0"]=None
										
				self.pod_switches_routing_tables["prefix"][f"10.{pod}.{switch}.1"][f"0.0.0.0"]=None
				
				for host in range(2, (self.k//2)+2):
					self.pod_switches_routing_tables["suffix"].setdefault(f"10.{pod}.{switch}.1",{})
					self.pod_switches_routing_tables["suffix"][f"10.{pod}.{switch}.1"][f"10.0.0.{host}"]=None
        
        

