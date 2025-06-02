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

class SPRouter(app_manager.RyuApp):
	
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
	def __init__(self, *args, **kwargs):
		super(SPRouter, self).__init__(*args, **kwargs)
		
		# Initialize the topology with #ports=4
		self.topo_net = topo.Fattree(4)
		
		self.datapath_to_ip={}
		
		self.datapath_port_to_ip={}
		
		self.switch_mac_to_port={}
		
		self.generate_datapath_to_ip(self.topo_net)

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
			
			self.datapath_port_to_ip.setdefault(src.dpid,{})
			self.datapath_port_to_ip.setdefault(dst.dpid,{})
			
			
			
			if src.port_no not in self.datapath_port_to_ip[src.dpid]:
				self.datapath_port_to_ip[src.dpid][src.port_no]=self.datapath_to_ip[dst.dpid]
				
			if dst.port_no not in self.datapath_port_to_ip[dst.dpid]:
				self.datapath_port_to_ip[dst.dpid][dst.port_no]=self.datapath_to_ip[src.dpid]
			print(self.datapath_port_to_ip)
		

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# Install entry-miss flow entry
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)


	# Add a flow entry to the flow-table
	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		# Construct flow_mod message and send it
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
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
			self.datapath_to_ip[core_s.unique_id.split("-")[1]]=core_s.ip
        	
		for pod_id in range(ft_topo.pods_count):
        
			#adding aggregate level switches to mininet
			for aggregate_s in ft_topo.switches[1][pod_id]:
				self.datapath_to_ip[aggregate_s.unique_id.split("-")[1]]=aggregate_s.ip
				
			
			#adding edge level switches to mininet
			for edge_s in ft_topo.switches[2][pod_id]:
				self.datapath_to_ip[edge_s.unique_id.split("-")[1]]=edge_s.ip
		
