import enum
import resource
import threading
import socketserver
import time
import signal
import logging

import openflow
from pypacker.layer12.ethernet import Ethernet

# https://osrg.github.io/ryu-book/en/html/spanning_tree.html

class EtherType(enum.IntEnum):
	IPv4  = 0x0800 # Internet Protocol version 4 (IPv4)
	ARP   = 0x0806 # Address Resolution Protocol (ARP)
	WOL   = 0x0842 # Wake-on-LAN[9]
	RARP  = 0x8035 # Reverse Address Resolution Protocol (RARP)
	VLAN  = 0x8100 # VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[10]
	SLPP  = 0x8102 # Simple Loop Prevention Protocol (SLPP)
	VLACP = 0x8103 # Virtual Link Aggregation Control Protocol (VLACP)
	IPv6  = 0x86DD # Internet Protocol Version 6 (IPv6)
	LLDP  = 0x88CC # Link Layer Discovery Protocol (LLDP)

def bytes_to_str(data: bytes) -> str:
	byte: bytes
	res = ':'.join(f'{byte:02X}' for byte in data)
	return res

class OpenFlowRequestHandler(socketserver.BaseRequestHandler):

	def get_msg(self) -> openflow.GenericMessage:
		data: bytes = self.request.recv(4096)
		if len(data) == 0:
			# I think this signals the end of communication.
			return None
		try:
			res: openflow.GenericMessage = openflow.unpack(data)
		except openflow.UnpackException:
			# Can this be generated if we don't read enough data?
			logging.log(logging.INFO, f'unable to parse {data}')
			return None
		logging.log(logging.INFO, f'received {res.header}')
		return res

	def handle(self):
		mac_to_port: dict[str, int] = {}
		logging.log(logging.INFO, 'starting to handle the request')
		while msg := self.get_msg():
			if msg.header.message_type == openflow.Type.OFPT_HELLO: break
			logging.log(logging.INFO, f'ignoring {msg.header}')
			# Probably there is a loop in the network.
		else:
			logging.log(logging.INFO, 'closing communication')
			return

		self.request.sendall(openflow.Hello(msg.header.xid).pack())
		self.request.sendall(openflow.FeaturesRequest(msg.header.xid).pack())

		while msg := self.get_msg():
			if msg.header.message_type == openflow.Type.OFPT_FEATURES_REPLY: break
			elif msg.header.message_type == openflow.Type.OFPT_ECHO_REQUEST:
				self.request.sendall(openflow.EchoReply(msg.header.xid, msg.data.value))
			else:
				logging.log(logging.INFO, f'ignoring {msg.header}')
				# Probably there is a loop in the network.
		else:
			logging.log(logging.INFO, 'closing communication')
			return

		dpid: str = msg.datapath_id.value
		capabilities = msg.capabilities

		# The setup is now done.

		while msg := self.get_msg():
			if msg.header.message_type == openflow.Type.OFPT_ECHO_REQUEST:
				self.request.sendall(openflow.EchoReply(msg.header.xid, msg.data.value).pack())
			elif msg.header.message_type == openflow.Type.OFPT_PACKET_IN:
				msg: openflow.PacketIn
				logging.log(logging.INFO, f'{msg.reason}')

				eth = Ethernet(msg.data.value)

				if eth.type_t == 'ETH_TYPE_LLDP':
					logging.log(logging.INFO, 'ignoring LLDP packet')
					return

				logging.log(logging.INFO, f'packet in {dpid=} {eth.src_s=} {eth.dst_s=} {msg.in_port=}')

				# learn a mac address to avoid FLOOD next time.
				mac_to_port[eth.src_s] = int(msg.in_port)

				out_port = mac_to_port[eth.dst_s] if eth.dst_s in mac_to_port else openflow.Port.OFPP_FLOOD
				out_port = openflow.Port.OFPP_FLOOD # REMOVE THIS.
				actions = [openflow.ActionOutput(out_port)]
				data = msg.data.value if msg.buffer_id == openflow.NO_BUFFER else None
				resp = openflow.PacketOut(msg.header.xid, msg.buffer_id, msg.in_port, actions, data)
				self.request.sendall(resp.pack())
			elif msg.header.message_type == openflow.Type.OFPT_PORT_STATUS:
				logging.log(logging.INFO, f'{msg.reason}')
			elif msg.header.message_type == openflow.Type.OFPT_ECHO_REPLY:
				logging.log(logging.INFO, 'unexpectedly receiving an echo reply')
			else:
				logging.log(logging.INFO, 'ignoring message')
			#self.request.sendall(StatsRequest(msg.xid, StatsType.OFPST_AGGREGATE).pack())
		logging.log(logging.INFO, f'{dpid} {mac_to_port}')

class OpenFlowServer(socketserver.ThreadingMixIn, socketserver.TCPServer): pass

def sigint_handler(signum, frame) -> None:
	global running
	running = False

if __name__ == '__main__':
	# '' means all interfaces.
	HOST, PORT = '', 6653

	limit = 2**36
	limits = (limit, limit)
	resource.setrlimit(resource.RLIMIT_DATA, limits)

	running = True
	signal.signal(signal.SIGINT, sigint_handler)

	logging.getLogger().setLevel(logging.INFO)
	FORMAT = '%(threadName)s %(asctime)s %(message)s'
	logging.basicConfig(format=FORMAT)

	server = OpenFlowServer((HOST, PORT), OpenFlowRequestHandler)
	with server:
		server_thread = threading.Thread(target=server.serve_forever)
		server_thread.daemon = True
		server_thread.start()
		while running: time.sleep(0.01)
		server.shutdown()
