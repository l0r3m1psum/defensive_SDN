#!/bin/sh
# This is a simple monitor for the bandwidth limits in the network.
while true
do
	for br in `ovs-vsctl list-br`
	do
		dpid=`ovs-vsctl --columns=datapath_id --format=csv list bridge $br | sed 1d | tr -d \"`
		for iface in `ovs-vsctl list-ifaces $br`
		do
			port=`ovs-vsctl --columns=ofport --format=csv list interface $iface | sed 1d`
			rate=`ovs-vsctl --columns=ingress_policing_rate --format=csv list interface $iface | sed 1d`
			echo $dpid,$port,$rate | nc 192.168.1.10 1024
		done
	done
	sleep 1
done

# cli.do_sh('ovs-vsctl set interface s1-eth1 ingress_policing_rate=10000 # h1 -> A')
# cli.do_sh('ovs-vsctl set interface s1-eth2 ingress_policing_rate=10000 # hm -> A')
# cli.do_sh('ovs-vsctl set interface s2-eth1 ingress_policing_rate=10000 # h2 -> B')
# cli.do_sh('ovs-vsctl set interface s3-eth1 ingress_policing_rate=10000 # h3 -> A')

# cli.do_sh('ovs-vsctl set interface s1-eth3 ingress_policing_rate=10000 # A -> B')
# cli.do_sh('ovs-vsctl set interface s2-eth2 ingress_policing_rate=10000 # B -> A')
# cli.do_sh('ovs-vsctl set interface s2-eth3 ingress_policing_rate=100   # B -> C')
# cli.do_sh('ovs-vsctl set interface s3-eth2 ingress_policing_rate=100   # C -> B')
# cli.do_sh('ovs-vsctl set interface s3-eth3 ingress_policing_rate=10000 # C -> A')
# cli.do_sh('ovs-vsctl set interface s1-eth4 ingress_policing_rate=10000 # A -> C')