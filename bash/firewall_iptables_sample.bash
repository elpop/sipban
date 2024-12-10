#!/bin/bash -x

# iptables program
ipt="/sbin/iptables"

# ipset
ipset="/usr/sbin/ipset"
ipset_name="blacklist"

# ip's
host_ip="93.184.215.14"
internal_ip="10.88.1.11"

# vpn
vpn_ip="10.1.1.1"
vpn_range="10.1.1.0/24"

# Interfaces
if_internet="eno1"
if_internal="eno2"
if_vpn="tun0"

# Spoof IP range
spoof_ips="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3"

# Clean iptables Rules
$ipt -t nat -F
$ipt -t nat -X
$ipt -t nat --policy PREROUTING ACCEPT
$ipt -t nat --policy POSTROUTING ACCEPT
$ipt -t nat --policy OUTPUT ACCEPT

$ipt -t mangle -F
$ipt -t mangle -X
$ipt -t mangle --policy PREROUTING ACCEPT
$ipt -t mangle --policy INPUT ACCEPT
$ipt -t mangle --policy FORWARD ACCEPT
$ipt -t mangle --policy OUTPUT ACCEPT
$ipt -t mangle --policy POSTROUTING ACCEPT

$ipt -t filter -F
$ipt -t filter -X
$ipt -t filter --policy INPUT ACCEPT
$ipt -t filter --policy FORWARD ACCEPT
$ipt -t filter --policy OUTPUT ACCEPT

$ipt --delete-chain
$ipt --zero

sleep 1

# Begin rules definition
$ipt -t filter --policy INPUT DROP
$ipt -t filter --policy OUTPUT ACCEPT
$ipt -t filter --policy FORWARD DROP

# table filter:

# This ipset and iptables rule are created by the blacklist.pl program. Only showed for didactic purposes
#$ipset create $ipset_name hash:ip hashsize 4096 timeout 604800
#$ipt -t filter -I INPUT -i $if_internet -m set --match-set $ipset_name src -j DROP

$ipt -t filter -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
$ipt -t filter -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$ipt -t filter -A INPUT -m conntrack --ctstate INVALID -j DROP

$ipt -t filter -A INPUT -i lo -j ACCEPT
$ipt -t filter -A INPUT -i $if_internal -j ACCEPT
$ipt -t filter -A INPUT -i $if_vpn -j ACCEPT

# SSH
$ipt -t filter -A INPUT -i $if_internet -p TCP -m tcp --dport 22 -j ACCEPT

# HTTP/ HTTPS
$ipt -t filter -A INPUT -i $if_internet -p TCP -m tcp --dport 80 -j ACCEPT
$ipt -t filter -A INPUT -i $if_internet -p TCP -m tcp --dport 443 -j ACCEPT

# Open VPN
$ipt -t filter -A INPUT -i $if_internet -p UDP -m udp --dport 1195 -j ACCEPT

# WebSockets
$ipt -t filter -A INPUT  -i $if_internet -p tcp -m multiport --dports 8081:8083,8089 -j ACCEPT

# SIP
$ipt -t filter -A INPUT  -i $if_internet -p udp -m multiport --dports 5060,10000:20001 -j ACCEPT

$ipt -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop packet that claiming from our own server on WAN port
#$ipt -t filter -A INPUT  -i $if_internet -s $host_ip -j DROP
#$ipt -t filter -A OUTPUT -o $if_internet -s $host_ip -j DROP

# Drop all spoofed
for spoof in $spoof_ips
do
 $ipt -t filter -A INPUT  -i $if_internet -s $spoof -j DROP
 $ipt -t filter -A OUTPUT -o $if_internet -s $spoof -j DROP
done

#para rutear entre miembros de la vpn
$ipt -t filter -A FORWARD -i $if_vpn -j ACCEPT
$ipt -t nat -A POSTROUTING -s $vpn_range -o $if_vpn -j MASQUERADE

$ipt -t filter -A OUTPUT -o lo -j ACCEPT
$ipt -t filter -A OUTPUT -o $if_internet -j ACCEPT
$ipt -t filter -A OUTPUT -o $if_internal -j ACCEPT

iptables-save > /etc/iptables/rules.v4

