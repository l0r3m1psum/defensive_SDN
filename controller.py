from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

import networkx

SHORTEST_PATH_FORWARDING = False

# This https://github.com/knetsolutions/learn-sdn-with-ryu/blob/master/ryu_part10.md contains the following useful
# links:
#   * https://sdn-lab.com/2014/12/25/shortest-path-forwarding-with-openflow-on-ryu/
#   * http://vlkan.com/blog/post/2013/08/06/sdn-discovery/
#   * https://github.com/castroflavio/ryu/blob/master/ryu/app/shortestpath.py
# This https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md contains the following useful links:
#   * https://sdn-lab.com/2014/12/31/topology-discovery-with-ryu/


# https://osrg.github.io/ryu-book/en/html/traffic_monitor.html

class Project5Controller(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		# For every datapath id this stores a dictionary that maps a MAC address to
		# the port where it came from.
		self.mac_to_port: dict[int, dict[str, int]] = {}
		# A graph that has the switches and host ad nodes and the links as edges.
		self.graph = networkx.DiGraph()
		self.monitor_thread = hub.spawn(self._monitor)
		self.datapaths: dict[int, Datapath] = {}
		# NOTE: self.datapaths and self.mac_to_port can probably be joined in a single data structure.

	@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
	def _port_status_handler(self, ev):
		msg = ev.msg
		reason = msg.reason
		port_no = msg.desc.port_no

		ofproto = msg.datapath.ofproto
		if reason == ofproto.OFPPR_ADD:
			self.logger.info("port added %s", port_no)
		elif reason == ofproto.OFPPR_DELETE:
			self.logger.info("port deleted %s", port_no)
		elif reason == ofproto.OFPPR_MODIFY:
			self.logger.info("port modified %s", port_no)
		else:
			self.logger.info("Illeagal port state %s %s", port_no, reason)

	# Network discovery.
	# NOTE: it is not super clear how EventSwitchEnter/EventSwitchLeave and EventOFPStateChange do different things and
	# yet are pretty much the same.
	# TODO: look into the documentation to solve this mystery.

	@set_ev_cls(event.EventSwitchEnter)
	def _switch_enter_handler(self, ev):
		"""Switches are learned when Hello messages and Features Replays are received, links are learned with the LLDP
		 protocol."""
		switch_list = get_switch(self, None)
		switches = [switch.dp.id for switch in switch_list]
		self.graph.add_nodes_from(switches)

		links_list = get_link(self, None)
		links_src_to_dst = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
		self.graph.add_edges_from(links_src_to_dst)
		links_dst_to_src = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
		self.graph.add_edges_from(links_dst_to_src)

	@set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
	def _switch_leave_handler(self, ev):
		self.graph.remove_node(ev.switch.dp.id)
		self.logger.info(f"Not tracking Switches, switch leaved {ev.switch.dp.id}.")

	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def _state_change_handler(self, ev):
		"""A controller is considered dead if it does not reply to an Echo Request after a certain amount of time. A
		switch is first discovered when it replies to a Hello message and its datapath learned when it responds to a
		Feature Request."""
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			if datapath.id not in self.datapaths:
				self.logger.debug('register datapath: %016x', datapath.id)
				self.datapaths[datapath.id] = datapath
				self.mac_to_port[datapath.id] = {}
		elif ev.state == DEAD_DISPATCHER:
			if datapath.id in self.datapaths:
				self.logger.debug('unregister datapath: %016x', datapath.id)
				del self.datapaths[datapath.id]
				del self.mac_to_port[datapath.id]

	# Traffic routing.

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			self.logger.debug('ignoring LLDP packet')
			return

		dpid = datapath.id

		self.logger.debug("packet in %s %s %s %s", dpid, eth.src, eth.dst, msg.in_port)

		# Here thanks to Packet In messages and MAC addresses we perform the last step of topology discovery: host
		# discovery.
		if SHORTEST_PATH_FORWARDING:
			assert dpid in self.mac_to_port, "_state_change_handler did not update self.mac_to_port correctly"
			# learn a mac address to avoid FLOOD next time.
			self.mac_to_port[dpid][eth.src] = msg.in_port

			if eth.dst in self.mac_to_port[dpid]:
				out_port = self.mac_to_port[dpid][eth.dst]
			else:
				out_port = ofproto.OFPP_FLOOD
		else:
			# updating the graph with hosts to avoid FLOOD next time
			if eth.src not in self.graph:
				self.graph.add_node(eth.src)
				self.graph.add_edge(dpid, eth.src, port=msg.in_port)
				self.graph.add_edge(eth.src, dpid)

			if eth.dst in self.graph:
				assert networkx.has_path(self.graph, eth.src, eth.dst), "how did we receive a packet if no path exists?"
				path = networkx.shortest_path(self.graph, eth.src, eth.dst)
				#path = networkx.dag_longest_path(self.graph, eth.src, eth.dst)
				next = path[path.index(dpid) + 1]
				out_port = self.graph[dpid][next]['port']
			else:
				out_port = ofproto.OFPP_FLOOD

		actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

		# (optional) install a flow to avoid packet_in next time
		# TODO: the flow has to be removed if the graph changes.
		if out_port != ofproto.OFPP_FLOOD:
			match = datapath.ofproto_parser.OFPMatch(
				in_port=msg.in_port,
				dl_dst=haddr_to_bin(eth.dst), dl_src=haddr_to_bin(eth.src))
			mod = datapath.ofproto_parser.OFPFlowMod(
				datapath=datapath, match=match, cookie=0,
				command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
				priority=ofproto.OFP_DEFAULT_PRIORITY,
				flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
			datapath.send_msg(mod)

		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = datapath.ofproto_parser.OFPPacketOut(
			datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
			actions=actions, data=data)
		datapath.send_msg(out)

	# Performance monitoring.

	def _monitor(self):
		while True:
			for datapath in self.datapaths.values():
				self.logger.debug('send stats request: %016x', datapath.id)
				ofproto = datapath.ofproto
				parser = datapath.ofproto_parser
				flags = 0
				port_no = ofproto.OFPP_NONE
				req = parser.OFPPortStatsRequest(datapath, flags, port_no)
				datapath.send_msg(req)
			hub.sleep(1)

	# OFPPortStats(
	#     port_no=65534,
	#     rx_packets=0,
	#     tx_packets=0,
	#     rx_bytes=0,
	#     tx_bytes=0,
	#     rx_dropped=8281,
	#     tx_dropped=0,
	#     rx_errors=0,
	#     tx_errors=0,
	#     rx_frame_err=0,
	#     rx_over_err=0,
	#     rx_crc_err=0,
	#     collisions=0
	# )

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def _desc_stats_reply_handler(self, ev):
		msg = ev.msg
		ofproto = msg.datapath.ofproto
		body = ev.msg.body
		dpid = msg.datapath.id

		for port in body:
			from ryu.ofproto.ofproto_v1_0_parser import OFPPortStats
			port: OFPPortStats
			# Weird magic number.
			if port.port_no == ofproto.OFPP_NONE - 1: continue
			self.logger.info(f"{dpid} {port.tx_bytes}")