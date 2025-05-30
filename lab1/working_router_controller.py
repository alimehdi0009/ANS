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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types, arp

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port={}
        
        self.ip_to_port={}
        
        self.arp_cache={}
        
        self.packet_buffer={}
        
        self.l2_broadcast_mac='ff:ff:ff:ff:ff:ff'
        self.l3_broadcast_mac='00:00:00:00:00:00'
        
        self.router_datapath_id=3
        self.s1_datapath_id=1
        self.s2_datapath_id=2
        # Here you can initialize the data structures you want to keep at the controller
        
        #
        
        self.port_to_own_mac = {
        	1: "00:00:00:00:01:01",
        	2: "00:00:00:00:01:02",
        	3: "00:00:00:00:01:03"
        }
        
        self.port_to_own_ip = {
        	1: "10.0.1.1",
        	2: "10.0.2.1",
        	3: "192.168.1.1"
        }
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        
        ofproto = datapath.ofproto
        
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)



    """Add a flow entry to the flow-table"""
    
    def add_flow(self, datapath, priority, match, actions,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
        	mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id,priority=priority,
        	match=match,instructions=inst)
        else:
        	mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
        	match=match, instructions=inst)
        
        datapath.send_msg(mod)



    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        self.log_headers(ev)
        
        msg = ev.msg
        datapath = msg.datapath
        
        # Your controller implementation should start here
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        received_packet = packet.Packet(msg.data)
        
        eth_pkt = received_packet.get_protocol(ethernet.ethernet)
        
        in_port = msg.match['in_port']

	        
        """ If received packet is of type ARP """
        if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
        	self.logger.info('=============== ARP Scope Start==================')
        		
        	arp_pkt = received_packet.get_protocol(arp.arp)
        		
        	#if ARP is a Request
        	
        	if arp_pkt.opcode == arp.ARP_REQUEST:
        	
        		#if ARP request arrives at a switch
        		
        		if datapath.id in [self.s1_datapath_id, self.s2_datapath_id]:
        
        			self.handle_switch(ev)
        		
        		#if arp request arrives at router
        		
        		elif datapath.id in [self.router_datapath_id]:
        		
        			self.handle_arp_request(datapath, in_port, eth_pkt,arp_pkt)
        			
        		else:
        			pass
        			
        	#If ARP is an arp reply
        	
        	elif arp_pkt.opcode == arp.ARP_REPLY:
        	
        		#if arp response arrives at a switch
        		
        		if datapath.id in [self.s1_datapath_id, self.s2_datapath_id]:
        			
        			#switch learning the source mac to port
        			
        			if arp_pkt.src_mac not in self.mac_to_port[datapath.id]:
        				self.mac_to_port[datapath.id][arp_pkt.src_mac] = in_port
        			
        			self.handle_switch(ev)
        		
        		#if arp response arrives at router
        		elif datapath.id in [self.router_datapath_id]:
        			
        			#router learning the source ip to mac in arp cache
        			
        			#if arp_pkt.src_ip not in self.arp_cache:
        				#self.arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac
        			
        			self.handle_arp_reply(ev)
        			
        		else:
        			pass
        #handling IP packet
        elif eth_pkt.ethertype == ether_types.ETH_TYPE_IP:
        
        	if datapath.id in [self.router_datapath_id]:
        		
        		self.handle_router(ev)
        		
        	elif datapath.id in [self.s1_datapath_id, self.s2_datapath_id]:
        		
        		self.handle_switch(ev)
        		
        	else:
        		pass
        		
        else:
        	if datapath.id in [self.s1_datapath_id, self.s2_datapath_id]:
        		self.handle_switch(ev)
        	elif datapath.id in [self.router_datapath_id]:
        		self.handle_router(ev)
        	else:
        		pass

    	
    
    """ log packet details """
    def log_headers(self,ev):
    
    	msg = ev.msg
    	
    	datapath=msg.datapath
    	
    	received_packet = packet.Packet(msg.data)
    	
    	eth_pkt = received_packet.get_protocol(ethernet.ethernet)
    	
    	arp_pkt = received_packet.get_protocol(arp.arp)
    	
    	ipv4_pkt = received_packet.get_protocol(ipv4.ipv4)
    	
    	self.logger.info('datapath: %s', datapath.id)
    	
    	self.logger.info('in port: %s', msg.match['in_port'])
    	
    	if eth_pkt:
    	
    		self.logger.info('eth source mac: %s',eth_pkt.src)
    		self.logger.info('eth destination mac: %s',eth_pkt.dst)
    	
    	if ipv4_pkt:
    		
    		self.logger.info('ipv4 source ip: %s',ipv4_pkt.src)
    		self.logger.info('ipv4 destination ip: %s',ipv4_pkt.dst)
    		
    	if arp_pkt:
    		
    		self.logger.info('arp source mac: %s',arp_pkt.src_mac)
    		self.logger.info('arp destination mac: %s',arp_pkt.dst_mac)
    		
    		self.logger.info('arp source ip: %s',arp_pkt.src_ip)
    		self.logger.info('arp destination ip: %s',arp_pkt.dst_ip)
    	
    	self.logger.info('========================== Mac to port ============================ ')
    	self.logger.info(self.mac_to_port)
    	self.logger.info('========================== Buffered Packets ============================= ')
    	self.logger.info(self.packet_buffer)
    	
    		
    	
    	
    		

    #=======================================switches Start========================================
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
    	#mac_to_port map then add  it (switch learning)
    	
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
    	
    	datapath.send_msg(packet_out)
    
    #=======================================switches End========================================
    
   
    
    #======================================router Start ========================================
    
    def handle_router(self,ev):
    	
    	msg = ev.msg
    	
    	datapath=msg.datapath
    	ofproto = datapath.ofproto
    	parser = datapath.ofproto_parser
    	
    	received_packet = packet.Packet(msg.data)
    	ip_header = received_packet.get_protocol(ipv4.ipv4)
    	ethernet_header = received_packet.get_protocol(ethernet.ethernet)
    	
    	if ip_header ==None:
    		return
    	
    	source_ip = ip_header.src
    	destination_ip = ip_header.dst
    	
    	datapath_id=datapath.id
    	in_port = msg.match['in_port']
    	
    	#getting first three octat for the destination ip address e.g 10.0.1
    	
    	dst_ip_3_oct = '.'.join(destination_ip.split('.')[:3])
    	
    	out_port=None
    	out_gateway_ip=None
    	
    	#learning the ip to port for sender host in the routers forwarding table
    	
    	if source_ip not in self.ip_to_port:
    	
    		self.ip_to_port[source_ip]=in_port
    	
    	#checking if there is en entry for destination ip in the forwarding table so that we get 
    	#output port (i.e learning forwarding table)
    	
    	
    	if destination_ip in self.ip_to_port:
    		out_port = self.ip_to_port[destination_ip]
    	else:
    	
    	#iterating the hardcoded routers port to ip mapping to check for destination subnet port
    		for gateway_port, gateway_ip in self.port_to_own_ip.items():
    			
    			out_gateway_ip = gateway_ip
    			
    			#getting first three octat for the router interface ip address e.g 10.0.1
    			gateway_3_oct = '.'.join(gateway_ip.split('.')[:3])
    			
    			
    			#matching if incoming ip matched the subnet ip. if yes then get the
    			#outport
    			
    			if gateway_3_oct == dst_ip_3_oct:
    				
    				out_port = gateway_port
    				
    				break
    				
    		self.logger.info('no ip entry found')
 
    	
    	#now that we have found the router's out interface for the received packet we check if we
    	#have mac address against the destination ip address in the router's arp cache. if yes get it
    	#and update the packet with that destination mac address
    	
    	
    	out_gateway_mac = self.port_to_own_mac[out_port]
    	
    	if destination_ip in self.arp_cache:
    		target_destination_mac = self.arp_cache[destination_ip]
    	else:
    		
    		#buffering the packet before sending the arp for mac resolution
    		
    		self.packet_buffer.setdefault(destination_ip, []).append((source_ip,datapath, in_port, msg.data))
    	
    		#if no  mac address for the destination in the local arp table then send an arp
    		#request to the router out interface
    		
    		self.send_arp(
    			datapath = datapath,
    			src_mac = out_gateway_mac,
    			src_ip = out_gateway_ip,
    			dst_mac = self.l2_broadcast_mac,
    			dst_ip = destination_ip,
    			out_port = out_port,
    			arp_opcode = arp.ARP_REQUEST)
    		return
    	
    	#adding open flow actions to update the destination mac address of the packet
    	actions = [
    	parser.OFPActionSetField(eth_dst=target_destination_mac),
    	parser.OFPActionSetField(eth_src=out_gateway_mac),
    	parser.OFPActionOutput(out_port)]
    	
    	#create a match for the new flow rule for the source ip to destination ip address
    	
    	match = parser.OFPMatch(ipv4_src = source_ip, ipv4_dst = destination_ip, eth_type=0x0800)
    		
    	self.add_flow(datapath, 1, match,actions)
    		
    	packet_out = parser.OFPPacketOut(
    		datapath=datapath,
    		buffer_id=msg.buffer_id,
    		in_port=in_port,
    		actions=actions,
    		data=msg.data)
    		
    	datapath.send_msg(packet_out)
    
    #======================================router end==========================================
    
    
    #=======================================Handle ARP Start =======================================
    def handle_arp_request(self, datapath, in_port, eth_pkt, arp_pkt):
    	
    	
    	ofproto = datapath.ofproto
    	parser = datapath.ofproto_parser
    	datapath_id = datapath.id
    	port_in = in_port
    	
    	source_ip = arp_pkt.src_ip
    	destination_ip = arp_pkt.dst_ip
    	
    	source_mac = eth_pkt.src
    	destination_mac = eth_pkt.dst
    	
    	target_source_mac=None
    	
    	if  datapath.id == self.router_datapath_id:
    	
    		#learning ip to port in router forwarding table
    		if source_ip not in self.ip_to_port:
    			self.ip_to_port[source_ip]=port_in
    			
    		#learning ip to mac in router local arp cache
    		if source_ip not in self.arp_cache:
    			self.arp_cache[source_ip]=source_mac
    	
    		#checking if destination ip is in router arp then we can provide requested mac
    		#address back to arp generating host/router
    		
    		if destination_ip in self.arp_cache:
    			target_source_mac = self.arp_cache[destination_ip]
    			
    		#if ip entry is not in router arp cache then we check if requested mac if for router
    		#itself? if yes then we get router interface mac based in the in port
    		
    		elif self.port_to_own_ip[port_in] == destination_ip:
    			target_source_mac=self.port_to_own_mac[port_in]
    			
    		else:
    			pass
    	
    		#sending the arp reply
    	
    		self.send_arp(
    			datapath = datapath,
    			src_mac = target_source_mac,
    			src_ip = destination_ip,
    			dst_mac = source_mac,
    			dst_ip = source_ip,
    			out_port = port_in,
    			arp_opcode = arp.ARP_REPLY)
    
    #================================================= Handle ARP END =============================
    
    
    #================================ Send ARP ============================================
    
    def send_arp(self,datapath, src_mac, src_ip, dst_mac, dst_ip, out_port, arp_opcode):
    	
    	#Creating an arp header with given opcode for the given parameters
    	arp_header= arp.arp(
    			opcode = arp_opcode,
    			src_mac = src_mac,
    			src_ip = src_ip,
    			dst_mac = dst_mac,
    			dst_ip=dst_ip
    		)
    	
    	#creating an ethernet header with given parameters
    	ether_header= ethernet.ethernet(
    		src=src_mac,
    		dst=dst_mac,
    		ethertype=ether_types.ETH_TYPE_ARP)
    	
    	#creating new packet with arp and ethernet headers
    	arp_packet = packet.Packet()
    	arp_packet.add_protocol(ether_header)
    	arp_packet.add_protocol(arp_header)
    	arp_packet.serialize()
    	
    	actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
    	
    	packet_out = datapath.ofproto_parser.OFPPacketOut(
    		datapath = datapath,
    		buffer_id = datapath.ofproto.OFP_NO_BUFFER,
    		in_port = datapath.ofproto.OFPP_CONTROLLER,
    		actions=actions,
    		data=arp_packet.data
    	)
    	
    	datapath.send_msg(packet_out)
    	
    	
    	
    #handle arp response
    def handle_arp_reply(self,ev):
    	
    	msg = ev.msg
    	datapath = msg.datapath
    	
    	ofproto = datapath.ofproto
    	parser = datapath.ofproto_parser
    	
    	in_port = msg.match['in_port']
    	
    	received_packet = packet.Packet(msg.data)
    	arp_pkt = received_packet.get_protocol(arp.arp)
    	
    	#router learning ip to mac from arp reply
    	
    	if arp_pkt.src_ip not in self.arp_cache:
    		self.arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac
    		
    	#checking if there are buffered packets for the source ip. If so then forward those
    	
    	if arp_pkt.src_ip in self.packet_buffer:
    		for src_ip, dpath, port, data in self.packet_buffer[arp_pkt.src_ip]:
    		
    			#creating a match to add a flow entry
    			match = parser.OFPMatch(
    			ipv4_src = src_ip, 
    			ipv4_dst = arp_pkt.src_ip,
    			eth_type=0x0800)
    			
    			#actions to update the packet source and destination mac addresses before forwarding
    			actions = [
    			parser.OFPActionSetField(eth_src=arp_pkt.dst_mac),
    			parser.OFPActionSetField(eth_dst=arp_pkt.src_mac),
    			parser.OFPActionOutput(in_port)]
    			
    			#creating a new flow
    			self.add_flow(datapath, 1, match,actions)
    			
    			#sending the packet out
    			out = parser.OFPPacketOut(
    				datapath=datapath,
    				buffer_id=ofproto.OFP_NO_BUFFER,
    				in_port=port,
    				actions=actions,
    				data=data)
    				
    			datapath.send_msg(out)
    			
    			#removing buffered packet after forwarding
    			del self.packet_buffer[arp_pkt.src_ip]
 
