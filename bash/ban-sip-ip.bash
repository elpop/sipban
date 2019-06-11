#!/bin/bash

ip="$(which iptables 2>/dev/null)"
ip=${ip:=/sbin/iptables}

if [[  -n "${@%:*}" ]]; then
#	$ip -t filter -D f2b-asterisk-tcp -j RETURN
#	$ip -t filter -D f2b-asterisk-udp -j RETURN
	$ip -t filter -D sipban-udp -j RETURN

#	$ip -t filter -A f2b-asterisk-tcp -s ${@%:*} -j REJECT --reject-with icmp-port-unreachable
#	$ip -t filter -A f2b-asterisk-udp -s ${@%:*} -j REJECT --reject-with icmp-port-unreachable
	$ip -t filter -A sipban-udp -s ${@%:*} -j REJECT --reject-with icmp-port-unreachable

#	$ip -t filter -A f2b-asterisk-tcp -j RETURN
#	$ip -t filter -A f2b-asterisk-udp -j RETURN
	$ip -t filter -A sipban-udp -j RETURN
fi
