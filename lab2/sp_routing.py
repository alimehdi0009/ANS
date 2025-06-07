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

from ryu.lib.packet import packet, ethernet, ipv4, ether_types, arp, icmp

import topo

class SPRouter(app_manager.RyuApp):
	
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
	def __init__(self, *args, **kwargs):
		super(SPRouter, self).__init__(*args, **kwargs)
		
		# Initialize the topology with #ports=4
		
		self.k=4
		
		self.topo_net = topo.Fattree(self.k)
		self.datapath_to_ip={}
		
		self.switch_possible_ports=list(range(1, self.k+1))
		
		self.paths={}
		
		self.datapath_port_to_connected_ip={}
		
		self.switch_mac_to_port={}
		
		self.datapath_to_ports={}
		
		self.generate_datapath_to_ip(self.topo_net)
		
		self.ip_to_datapath={ ip: dp for dp, ip in self.datapath_to_ip.items()}
		
		self.dijkistra = Dijkistra(self.topo_net.ip_flat_graph)

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
			
			self.datapath_port_to_connected_ip.setdefault(src.dpid,{})
			self.datapath_port_to_connected_ip.setdefault(dst.dpid,{})
			
			self.datapath_to_ports.setdefault(src.dpid,[])
			self.datapath_to_ports.setdefault(dst.dpid,[])
			
			if src.port_no not in self.datapath_port_to_connected_ip[src.dpid]:
				dst_ip=self.datapath_to_ip[dst.dpid]
				self.datapath_port_to_connected_ip[src.dpid][dst_ip]=src.port_no
				
			if src.port_no not in self.datapath_to_ports[src.dpid]:
				self.datapath_to_ports[src.dpid].append(src.port_no)
				
			if dst.port_no not in self.datapath_port_to_connected_ip[dst.dpid]:
				src_ip=self.datapath_to_ip[src.dpid]
				self.datapath_port_to_connected_ip[dst.dpid][src_ip]=dst.port_no
			
			if dst.port_no not in self.datapath_to_ports[dst.dpid]:
				self.datapath_to_ports[dst.dpid].append(dst.port_no)
		

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
		
		eth_pkt = received_packet.get_protocol(ethernet.ethernet)
		
		src = None
		dst = None
		shortest_path=None
		
		if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
		
			arp_header = received_packet.get_protocol(arp.arp)
			src=arp_header.src_ip
			dst=arp_header.dst_ip
			
		elif eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
		
			ipv4_header = received_packet.get_protocol(ipv4.ipv4)
			src=ipv4_header.src
			dst=ipv4_header.dst
			
		else:
			return
		
		if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP or eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
			
			current_datapath_ip=self.datapath_to_ip[dpid]
			
			if 1==1: #arp_header.opcode == arp.ARP_REQUEST or arp_header.opcode == arp.ARP_REPLY:
				
			
				if dpid not in self.datapath_port_to_connected_ip:
					self.datapath_port_to_connected_ip.setdefault(dpid,{})
					
				if src not in self.datapath_port_to_connected_ip[dpid]:
					self.datapath_port_to_connected_ip[dpid][src] = in_port
				
				if dpid not in self.datapath_to_ports:
					self.datapath_to_ports.setdefault(dpid,[])
				
				if in_port not in self.datapath_to_ports[dpid]:
					self.datapath_to_ports[dpid].append(in_port)
					
				if (src,dst) in self.paths:
					shortest_path = self.paths[(src,dst)]
				
				else:
					shortest_path=self.dijkistra.run(src,dst)
					
					if shortest_path:
						self.paths.setdefault((src,dst),[])
						self.paths[(src,dst)]=shortest_path
				
				
				if shortest_path and current_datapath_ip in shortest_path:
				
					current_dp_index=shortest_path.index(current_datapath_ip)
			
					next_dp_index = current_dp_index + 1
			
					if next_dp_index < len(shortest_path)-1:
				
						next_dp_ip = shortest_path[next_dp_index]		
			
						#getting current datapath port where next datapath is connected
						out_port = self.datapath_port_to_connected_ip[dpid][next_dp_ip]
			
						actions = [parser.OFPActionOutput(out_port)]
			
						match = parser.OFPMatch(in_port=in_port, ipv4_src = src, ipv4_dst = dst, eth_type=0x0800)
			
						self.add_flow(datapath, 1, match,actions)
			
						packet_out = parser.OFPPacketOut(
							datapath=datapath,
							buffer_id=msg.buffer_id,
							in_port=in_port,
							actions=actions,
							data=msg.data)
							
						datapath.send_msg(packet_out)
				
					elif next_dp_index == len(shortest_path)-1:
				
						last_dp_ip = shortest_path[next_dp_index-1]
				
						if dst in self.datapath_port_to_connected_ip[dpid]:
							
							out_port = self.datapath_port_to_connected_ip[dpid][dst]
							
							
							actions = [parser.OFPActionOutput(out_port)]
							match = parser.OFPMatch(in_port=in_port, ipv4_src = src, ipv4_dst = dst, eth_type=0x0800)
							self.add_flow(datapath, 1, match,actions)
					
							packet_out = parser.OFPPacketOut(
								datapath=datapath,
								buffer_id=msg.buffer_id,
								in_port=in_port,
								actions=actions,
								data=msg.data)
					
							datapath.send_msg(packet_out)
						else:
								
							existing_datapath_ports=self.datapath_to_ports[dpid]
								
							missing_ports = list(set(self.switch_possible_ports) - set(existing_datapath_ports))
					
							for out_port in missing_ports:
								actions = [parser.OFPActionOutput(out_port)]
								#match = parser.OFPMatch(in_port=in_port, ipv4_src = src, ipv4_dst = dst, eth_type=0x0800)
								#self.add_flow(datapath, 1, match,actions)
						
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

