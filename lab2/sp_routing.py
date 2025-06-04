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


from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

from dijkstra import Dijkistra

from ryu.lib.packet import packet, ethernet, ipv4, ether_types, arp

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
		
		self.datapath_routing_tables={}
		
		self.dijkistra = Dijkistra(self.topo_net.flat_graph)

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


		#for dp in self.datapath_port_to_ip:
		#	if dp >=300 and dp < 400:
		#		print(self.datapath_port_to_ip[dp])
		

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
		
		in_port = msg.match['in_port']
		
		received_packet = packet.Packet(msg.data)
		
		arp_header = received_packet.get_protocol(arp.arp)
		
		ip_header = received_packet.get_protocol(ipv4.ipv4)
		
		src = None
		dst = None
		
		if arp_header is not None:
			print(f"source: {arp_header.src_ip}")
			print(f"destination: {arp_header.dst_ip}")
			
			src=arp_header.src_ip
			dst=arp_header.dst_ip
			shortest_path=self.dijkistra.run(arp_header.src_ip,arp_header.dst_ip)
			
			#print(shortest_path)
		elif ip_header is not None:
			src = ip_header.src
			dst = ip_header.dst
			print(f"source: {ip_header.src}")
			print(f"destination: {ip_header.dst}")
			
		if src and dst:
			if datapath.id not in self.datapath_port_to_ip:
				self.datapath_port_to_ip.setdefault(datapath.id,{})
		
			if in_port not in self.datapath_port_to_ip[datapath.id]:
				self.datapath_port_to_ip[datapath.id][in_port] = dst
				print(f'added port: {in_port} for datapath:{datapath.id} againt dst: {dst}')
			
		
		""""received_packet = packet.Packet(msg.data)
		eth_pkt = received_packet.get_protocol(ethernet.ethernet)
		in_port = msg.match['in_port']
		
		
		if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
			self.logger.info('=============== ARP Scope Start==================')
			arp_pkt = received_packet.get_protocol(arp.arp)
			
			#if ARP is a Request
			
			if arp_pkt.opcode == arp.ARP_REQUEST:
			
				self.handle_switch(ev)
			
			#If ARP is a response
			elif arp_pkt.opcode == arp.ARP_REPLY:
			
				if arp_pkt.src_mac not in self.mac_to_port[datapath.id]:
					self.mac_to_port[datapath.id][arp_pkt.src_mac] = in_port
					
				self.handle_switch(ev)
        
		else:
			self.handle_switch(ev)


	def handle_switch(self,ev):
		
		msg = ev.msg
		
		datapath=msg.datapath
		
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		received_packet = packet.Packet(msg.data)
		
		ethernet_header = received_packet.get_protocol(ethernet.ethernet)
		destination_mac = ethernet_header.dst
		source_mac = ethernet_header.src
		datapath_id=datapath.id
		
		in_port = msg.match['in_port']
		
		#if switch doesn't have mac address to port entry for the received packet in 
		#mac_to_port map then add  it
		
		self.mac_to_port.setdefault(datapath_id, {})
		
		if source_mac not in self.mac_to_port[datapath_id]:
			self.mac_to_port[datapath_id][source_mac] = in_port
			#check if mac to port map already has an entry for the received mac address. if yes
			#get the outport
			
			out_port=None
			
		if destination_mac in self.mac_to_port[datapath_id]:
			out_port = self.mac_to_port[datapath_id][destination_mac]
		else:
			#if not entry found in the mac to port map then output port is Flood port.
			#it can also be the case for the arp request from the host/router
			
			self.logger.info('setting flood port: %s',ofproto.OFPP_FLOOD)
			out_port = ofproto.OFPP_FLOOD
		
		#creating the action for the flow rule with selected out port
		actions = [parser.OFPActionOutput(out_port)]
		
		#if out port is not the Flood port then we need to create a match for source and destination
		#mac addresses for incoming port to add new flow rule
		
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=destination_mac, eth_src=source_mac)
			self.add_flow(datapath, 1, match,actions)
			
		packet_out = parser.OFPPacketOut(
			datapath=datapath,
    			buffer_id=msg.buffer_id,
    			in_port=in_port, 
    			actions=actions,
    			data=msg.data)
    		
    		datapath.send_msg(packet_out)"""



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
		
