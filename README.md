# Network Tomography

The topic of the homework is to do network tomography with OpenFlow switches.
[This](https://www.amazon.com/Network-Tomography-Identifiability-Measurement-Inference/dp/1108421482)
seems to be a good book about the topic.

To be able to simulate a computer network we use Linux's namespaces (i.e.
process virtualization) and [Open vSwitch](https://www.openvswitch.org).

To make this <q>easy</q> the professor proposes to use
[Mininet](http://mininet.org/) and [Ryu](https://ryu-sdn.org).

But since a lot of stuff can be done directly from the Open vSwitch command line
interface ([`ovs-ofctl`](https://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.html)),
I can probably get away with mush less.

Please note that mininet uses nameless/anonymous/unnamed namespaces, to see them,
once they are created it is sufficient to use the command `ip netns list-id`.
Here a few sources from a [mailing list](https://mailman.stanford.edu/pipermail/mininet-discuss/2014-July/004827.html)
and the usual [StackOverflow](https://unix.stackexchange.com/questions/633919/).
To list all the OpenVSwitch bridges/switches the commands `ovs-vsctl show` and
`ovs-vsctl list-br`, it seems that they must be run from the current user to see
the switches.


[This video](https://youtube.com/watch?v=_WgUwUf1d34) shows how to create
network namespaces by hand and how to connect them! It is perfect for what I
want to do. some usefull comand to look into are: `ip(1)` and `brctl(1)`, the
second one seems to be a way to connect network namespaces without Openflow
capabilities.

[This](https://docs.openvswitch.org/en/latest/faq/openflow/) is some useful
documentation about using Openflow with Open vSwitch.

[This](http://mininet.org/overview/#how-it-works) describes how Mininet works at
a high level. The `mininet(1)` command is written mostly in Python but it is
based on [this](https://github.com/mininet/mininet/blob/master/mnexec.c) tiny C
program which executes commands in separated network namespaces.

[Wireshark](https://wireshark.org) or [tcpdump](https://tcpdump.org) can be used
to sniff Openflow traffic because it runs on top of TCP, as shown in [this
video](https://youtube.com/watch?v=fxfhXX3T9Vc).

A [cool reference](https://randomsecurity.dev/posts/openvswitch-cheat-sheet/) of
OpenVSwitch commands.

If you have networks with loops in mininet [here](https://github.com/mininet/mininet/wiki/FAQ#ethernet-loops)
is the solution.

[A basic OpenFlow controller written in C](https://github.com/noxrepo/openflow/blob/master/controller/controller.c).

`ovs-vsctl set-controller s1 tcp:localhost:6633` must be used to make the 
[Installing the default controller](http://installfights.blogspot.com/2016/12/exception-could-not-find-default.html)