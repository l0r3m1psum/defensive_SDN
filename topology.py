'''To create the topoogy listed in this file you just have to execute the
following command:
$ sudo mn --switch ovsbr,stp=1 --custom topology.py --topo project5 --test pingall

This command should let you visualize the custom topology in miniedit:
$ sudo python2.7 /usr/share/doc/mininet/examples/miniedit.py --custom topology.py --topo=project5

To execute this file with a remote controller use the following command:
$ sudo mn --switch ovs,protocols=OpenFlow10,stp=1 --controller remote,ip=192.168.0.191 --custom topology.py --topo project5 --test pingall
(the Spanning Tree Protocol (stp) option seems to be ignored)

Documentation can be found at:
  * https://mininet.github.io/api/hierarchy.html
  * https://docs.mininet.org

To se the flows installed in a switch use `ovs-ofctl dump-flows <switch-name>`.
You can also use `dpctl dump-flows`.

https://sreeninet.wordpress.com/2014/11/30/mininet-internals-and-network-namespaces/

https://docs.openvswitch.org/en/latest/howto/qos/
ovs-vsctl list-br # list all the bridges i.e. s1...sn
ovs-vsctl list-ifaces <bridge> # list all interfaces attached to a bridge i.e. s0-eth1
ovs-vsctl list interface <iface> # list all the properties o an interface
ovs-vsctl set interface s1-eth1 ingress_policing_rate=10000
sudo tc qdisc show dev s1-eth1

arp -n
'''
import re
import threading
import socket
import subprocess
import time
from typing import List

from mininet.cli import CLI
from mininet.link import TCLink, OVSLink, Link, Intf, TCIntf  # TC stands for traffic control.
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, OVSBridge, Host, Switch
from mininet.node import RemoteController
from mininet.topo import Topo

CONTROLLER_IP = '192.168.1.10'

class MyTopo(Topo):

	def build(self):
		leftHost = self.addHost('h1')
		rightHost = self.addHost('h2')
		leftSwitch = self.addSwitch('s3')
		rightSwitch = self.addSwitch('s4')

		self.addLink(leftHost, leftSwitch)
		self.addLink(leftSwitch, rightSwitch)
		self.addLink(rightSwitch, rightHost)


class Project5(Topo):
	def build(self):
		h1 = self.addHost('h1')
		h2 = self.addHost('h2')
		h3 = self.addHost('h3')
		hm = self.addHost('hm')

		s1 = self.addSwitch('s1')
		s2 = self.addSwitch('s2')
		s3 = self.addSwitch('s3')
		s4 = self.addSwitch('s4')

		self.addLink(h1, s1, bw=1000)
		self.addLink(hm, s1, bw=1000)
		self.addLink(h2, s2, bw=1000)
		self.addLink(h3, s3, bw=1000)
		self.addLink(s1, s2, bw=10)
		self.addLink(s2, s3, bw=4)
		self.addLink(s3, s1, bw=10)
		self.addLink(s4, s2, bw=10)
		self.addLink(s4, h3, bw=1000)

topos = {
	'mytopo': lambda: MyTopo(),
	'project5': lambda: Project5(),
}

def bandwidth_monitor(switches: List[Switch]):
	unit2factor = {
		'': 1,
		'bit': 1,
		'Kbit': 1_000,
		'Mbit': 1_000_000,
		'Gbit': 1_000_000_000,
		'Tbit': 1_000_000_000_000,
		'bps': 8,
		'Kbps': 8_000,
		'Mbps': 8_000_000,
		'Gbps': 8_000_000_000,
		'Tbps': 8_000_000_000_000,
	}
	regex = re.compile('rate ([0-9]+)([KMGT]?(:?bit|bps)?)')
	while True:
		for switch in switches:
			for intf, port in switch.ports.items():
				intf: Intf
				port: int
				if not isinstance(intf, TCIntf):
					continue
				intf: TCIntf
				proc = subprocess.run(['tc', 'class', 'show', 'dev', intf.name], capture_output=True, text=True)
				match = regex.search(proc.stdout)
				if not match:
					raise ValueError(f'rate not found or malformed: {proc.stdout}')
				number = int(match.group(1))
				unit = unit2factor[match.group(2)]
				rate = number * unit
				try:
					with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
						s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
						s.connect((CONTROLLER_IP, 1024))
						s.sendall(f'{switch.dpid},{port},{rate}'.encode())
				except OSError:
					print('monitor error')
					pass
			time.sleep(1)

def main():
	setLogLevel('info')
	c0 = RemoteController('c0', CONTROLLER_IP, 6653)
	net = Mininet(
		topo=Project5(),
		switch=OVSSwitch,
		host=Host,
		controller=c0,
		link=TCLink,
		cleanup=True,
		autoSetMacs=True,
		autoStaticArp=True,
		waitConnected=True
	)
	net.start()
	net.configLinkStatus('s4', 's2', 'down')
	net.configLinkStatus('s4', 'h3', 'down')
	net.pingAll()

	h1: Host = net.getNodeByName('h1')
	h3: Host = net.getNodeByName('h3')
	s1: Switch = net.getNodeByName('s1')
	s2: Switch = net.getNodeByName('s2')
	s3: Switch = net.getNodeByName('s3')

	# NOTE: cli.do_pingpair('h1 h2') seems to be broken.

	monitor = threading.Thread(None, bandwidth_monitor, 'monitor', (net.switches,), daemon=True)
	monitor.start()
	# cli = CLI(net, script='empty.txt')  # This is the only way that I have found to create a batch shell.
	_ = h1.cmd('ping', h3.IP(), """| while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done >h1.txt &""")
	_ = h1.cmd('ping', h3.IP(), """| while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done >h2.txt &""")
	# h1 ping -i 0.5 h2
	time.sleep(11)

	# Attack 1
	s1_s2: Link = net.linksBetween(s1, s2)[0]
	s1_s2.intf1.config(bw=1)
	s1_s2.intf2.config(bw=1)
	print()

	time.sleep(11)

	# Attack 2
	s2_s3: Link = net.linksBetween(s2, s3)[0]
	s2_s3.intf1.config(bw=1)
	s2_s3.intf2.config(bw=1)
	print()
	time.sleep(11)
	net.configLinkStatus('s4', 's2', 'up')
	net.configLinkStatus('s4', 'h3', 'up')

	time.sleep(11)
	# cli.cmdloop()

	net.stop()

	return 0


if __name__ == '__main__':
	raise SystemExit(main())
