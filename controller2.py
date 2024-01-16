"""This module contains...

OpenFlow (1.0) specification: https://opennetworking.org/wp-content/uploads/2013/04/openflow-spec-v1.0.0.pdf
Ryu documentation: https://ryu.readthedocs.io/en/latest/ofproto_v1_0_ref.html
The HTML version of the Ryu book: https://osrg.github.io/ryu-book/en/html
A good blog about OpenFlow: https://sdn-lab.com/

./venv/bin/ryu-manager
--log-config-file log_config.txt --enable-debugger --observe-links controller2.py
"""

import ryu.app
import ryu.app.ofctl.api
import ryu.base.app_manager
import ryu.controller.event
import ryu.controller.handler
import ryu.controller.ofp_event
import ryu.lib.hub
import ryu.lib.mac
import ryu.lib.packet.ether_types
import ryu.lib.packet.ethernet
import ryu.lib.packet.packet
import ryu.ofproto.ofproto_v1_0
import ryu.topology.event
import ryu.topology.switches

import networkx

import logging

DEFAULT_BW = 10_000_000_000 # The default bandwidth is 10 gigabits.
STATS_SAMPLING_INTERVAL = 1 # Second.
RECV_SIZE = 4096 # Bytes
BANDWIDTH_PORT = 1024

class EventBandwidthUpdate(ryu.controller.event.EventBase):
	"""An Event to notify the application about the bandwidth of a switch port."""
	def __init__(self, dpid: int, port: int, bw: int):
		super().__init__()
		self.dpid = dpid
		self.port = port
		self.bw = bw # expressed in bits per second

def get_edge_from_node_with_attribute(graph: networkx.Graph, node, edge_attribute: dict) -> tuple:
	for adj_node, edge_attributes in graph.adj[node].items():
		# This is true only in the case in which edge_attribute is a subset of edge_attributes.
		if edge_attributes | edge_attribute == edge_attributes:
			return adj_node, edge_attributes
	return None, None

"""
The graph in the controller should respect the following invariants:
  * all the nodes should be either instances of int (i.e. datapath ids) or str (i.e. MAC addresses)
  * all edges should have the attributes port, bw and tx
    - if the edge is form MAC address to dpid port should be OFPP_NONE
    - bw > 0
    - tx >= 0
    - 0 <= port <= ofproto.OFPP_MAX
  * two MAC addresses should never be connected directly
  * all edges should always be bidirectional
  * all edges should have different port numbers
"""

FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=FORMAT)

class Project5Controller(ryu.base.app_manager.RyuApp):
	"""Controller to help do the measurements described in project 5."""
	OFP_VERSIONS = [ryu.ofproto.ofproto_v1_0.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		# Here we store the network topology, together with output ports to reach the connected node and bandwidth
		# information for smart routing.
		self.net = networkx.DiGraph()
		ryu.lib.hub.spawn(self._bandwidth_monitor)
		ryu.lib.hub.spawn(self._stats_monitor)

	# This section of the code keeps self.net up to date (except for host information which is updated later in the
	# code).

	# Thanks to the OpenFlow handshake i.e. Hello and Feature Request messages.
	@ryu.controller.handler.set_ev_cls(ryu.topology.event.EventSwitchEnter)
	def _switch_enter_handler(self, ev: ryu.topology.event.EventSwitchEnter):
		switch: ryu.topology.switches.Switch = ev.switch
		dpid: int = switch.dp.id
		self.logger.info(f'The switch %d entered', dpid)
		self.net.add_node(dpid)

	@ryu.controller.handler.set_ev_cls(ryu.topology.event.EventSwitchLeave)
	def _switch_leave_handler(self, ev: ryu.topology.event.EventSwitchLeave):
		dpid: int = ev.switch.dp.id
		self.logger.info(f'The switch %d left', dpid)
		self.net.remove_node(dpid)

	# Thanks to LLDP.
	@ryu.controller.handler.set_ev_cls(ryu.topology.event.EventLinkAdd)
	def _link_add_handler(self, ev: ryu.topology.event.EventLinkAdd):
		link: ryu.topology.switches.Link = ev.link
		src_dpid: int = link.src.dpid
		dst_dpid: int = link.dst.dpid
		self.logger.info(f'A link from switch %d to %d was added', src_dpid, dst_dpid)
		# add_edge(u, v, port=n): to go from switch u to v the packet needs to get out port n (of the switch u itself).
		self.net.add_edge(src_dpid, dst_dpid, port=link.src.port_no, bw=DEFAULT_BW, tx=0)
		self.net.add_edge(dst_dpid, src_dpid, port=link.dst.port_no, bw=DEFAULT_BW, tx=0)

	@ryu.controller.handler.set_ev_cls(ryu.topology.event.EventLinkDelete)
	def _link_delete_handler(self, ev: ryu.topology.event.EventLinkDelete):
		link: ryu.topology.switches.Link = ev.link
		src_dpid: int = link.src.dpid
		dst_dpid: int = link.dst.dpid
		self.logger.info(f'A link from switch %d to %d was deleted', src_dpid, dst_dpid)
		# Since the edges are deleted automatically when a node attached to them is deleted we check first.
		if self.net.has_edge(src_dpid, dst_dpid): self.net.remove_edge(src_dpid, dst_dpid)
		if self.net.has_edge(dst_dpid, src_dpid): self.net.remove_edge(dst_dpid, src_dpid)

	# Here we expect another process to keep us up to date on this information.
	def _bandwidth_monitor(self):
		socket = ryu.lib.hub.listen(('', BANDWIDTH_PORT))
		while True:
			conn, _ = socket.accept()
			with conn:
				data: bytes = conn.recv(RECV_SIZE)
				csv = data.decode()
				dpid, port, bw = csv.split(',')
				event = EventBandwidthUpdate(int(dpid), int(port), int(bw))
				self.send_event(self.__class__.__name__, event)

	@ryu.controller.handler.set_ev_cls(EventBandwidthUpdate)
	def _bandwidth_update_handler(self, ev: EventBandwidthUpdate):
		if self.net.has_node(ev.dpid):
			self.logger.debug('Received bandwidth update for port %d of switch %d', ev.port, ev.dpid)
			_, edge_attrs = get_edge_from_node_with_attribute(self.net, ev.dpid, {'port': ev.port})
			if edge_attrs:
				edge_attrs['bw'] = ev.bw
			else:
				# This can happen if there are multiple path to a host and the one of them is never selected as a path.
				# Implementing ARP could solve this "problem".
				self.logger.error('Received bandwidth update for non existent port %d of switch %d', ev.port, ev.dpid)
		else:
			self.logger.error('Received bandwidth update for non existent switch %d', ev.dpid)

	# This part of the code is responsible for traffic routing. All EventOFP... Are automatically generated, therefore
	# are not present in the source of the ryu.controller.ofp_event module.

	@ryu.controller.handler.set_ev_cls(ryu.controller.ofp_event.EventOFPPacketIn)
	def _packet_in_handler(self, ev: ryu.controller.ofp_event.EventOFPPacketIn):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		dpid: int = datapath.id

		pkt = ryu.lib.packet.packet.Packet(msg.data)
		eth = pkt.get_protocol(ryu.lib.packet.ethernet.ethernet)

		if eth.ethertype == ryu.lib.packet.ether_types.ETH_TYPE_LLDP:
			self.logger.debug('ignoring LLDP packet from %d', dpid)
			return

		if eth.ethertype == ryu.lib.packet.ether_types.ETH_TYPE_ARP:
			self.logger.error('received an ARP packet from %d. This should never happen, set autoStaticArp=True in '
			                  'mininet', dpid)
			return

		self.logger.debug("Packet in switch %s from %s to %s using port %s", dpid, eth.src, eth.dst, msg.in_port)

		# Updating the graph with hosts to avoid FLOOD next time.
		if eth.src not in self.net:
			self.net.add_node(eth.src)
			# TODO: I have to make sure that the number of the input port is not already in the edges.
			self.net.add_edge(dpid, eth.src, port=msg.in_port, bw=DEFAULT_BW, tx=0)
			self.net.add_edge(eth.src, dpid, port=ofproto.OFPP_NONE, bw=DEFAULT_BW, tx=0)
			self.logger.info('A host with MAC address %s was added', eth.src)

		if eth.dst not in self.net:
			self.logger.info('Unknown destination %s, flooding', eth.dst)
			out_port = ofproto.OFPP_FLOOD
		elif not networkx.has_path(self.net, dpid, eth.dst):
			self.logger.info('Unable to find path from %d to %s, probably the controller was launched in the middle of '
			                 'some network activity', dpid, eth.dst)
			self.net.remove_node(eth.dst)
			out_port = ofproto.OFPP_FLOOD
		else:
			self.logger.info('Selecting the shortest route from %d to %s', dpid, eth.dst)
			path = networkx.shortest_path(self.net, dpid, eth.dst, weight=lambda u, v, attrs: DEFAULT_BW//attrs['bw'])
			# path = networkx.shortest_path(self.net, dpid, eth.dst, weight=lambda u, v, attrs: attrs['bw'])
			assert all(isinstance(node, int) for node in path[0:1:len(path)-1]), 'the path tries to pass through a host'
			next_node = path[1]
			out_port = self.net[dpid][next_node]['port']

		actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

		# (optional) install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			self.logger.info(f'Modifying flow table of switch %d', dpid)
			match = datapath.ofproto_parser.OFPMatch(
				in_port=msg.in_port,
				dl_dst=ryu.lib.mac.haddr_to_bin(eth.dst),
				dl_src=ryu.lib.mac.haddr_to_bin(eth.src))
			mod = datapath.ofproto_parser.OFPFlowMod(
				datapath=datapath, match=match, cookie=0,
				command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=10, # In seconds.
				priority=ofproto.OFP_DEFAULT_PRIORITY,
				flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
			datapath.send_msg(mod)

		data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
			actions=actions, data=data)
		datapath.send_msg(out)

	# This section of the code is responsible for monitoring the performance of the network.

	def _stats_monitor(self):
		while True:
			for node in self.net.nodes:
				if not isinstance(node, int): continue
				dpid = node
				datapath = ryu.app.ofctl.api.get_datapath(self, dpid)
				ofproto = datapath.ofproto
				parser = datapath.ofproto_parser
				flags = 0
				port_no = ofproto.OFPP_NONE
				req = parser.OFPPortStatsRequest(datapath, flags, port_no)
				datapath.send_msg(req)
			ryu.lib.hub.sleep(STATS_SAMPLING_INTERVAL)

	@ryu.controller.handler.set_ev_cls(ryu.controller.ofp_event.EventOFPPortStatsReply)
	def _desc_stats_reply_handler(self, ev: ryu.controller.ofp_event.EventOFPPortStatsReply):
		msg = ev.msg
		ofproto = msg.datapath.ofproto
		dpid = msg.datapath.id

		for port_stats in msg.body:
			port_stats: msg.datapath.ofproto_parser.OFPPortStats
			if port_stats.port_no > ofproto.OFPP_MAX: continue
			adj_node, edge_attributes = get_edge_from_node_with_attribute(self.net, dpid, {'port': port_stats.port_no})
			if not edge_attributes:
				continue # In the case in which we haven't discovered the host yet the port is not known in self.net.
			if edge_attributes['bw'] == 0:
				self.logger.error('The bandwidth of port %d of %d is 0 this should never happen', port_stats.port_no,
				                  dpid)
				continue
			assert port_stats.tx_bytes >= edge_attributes['tx'], 'did the counter overflow?'
			bandwidth = edge_attributes['bw']
			tx = (port_stats.tx_bytes - edge_attributes['tx']) * 8
			assert tx >= 0, f"{port_stats.tx_bytes=} {edge_attributes['tx']=} {dpid=} {port_stats.port_no=}"
			# The utilization may be higher than one, and that's ok because Linux's TC is not perfect.
			self.logger.info(f"Link between {dpid} and {adj_node} utilization {tx/STATS_SAMPLING_INTERVAL/bandwidth:.5f}")
			edge_attributes['tx'] = port_stats.tx_bytes

	# Miscellaneous.

	@ryu.controller.handler.set_ev_cls(ryu.controller.ofp_event.EventOFPErrorMsg)
	def _error_msg_handler(self, ev: ryu.controller.ofp_event.EventOFPErrorMsg):
		self.logger.error('OpenFLow error: %s', ev.msg)
