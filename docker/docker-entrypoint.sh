#!/bin/bash

cat > /etc/sipban.conf <<ENDLINE
# SipBan Configuration File

# Parameters to connect to Asterisk AMI
[ami]
port = "${AMI_PORT}"
user = "${AMI_USER}"
pass = "${AMI_PASS}"
host = "${AMI_HOST}"
ping = 600

# Port to send commands
[control]
port = "${SIPBANPORT}"

# Timers
[timer]
ban = 86400

#Iptables rules actions config
[iptables]
path  = "/sbin/"
chain = "sipban-udp"
rule  = "REJECT --reject-with icmp-port-unreachable"
#rule  = "DROP"
white_list = "/etc/sipban.wl"
dump = "/etc/sipban.dump"

# Log file
[log]
file = "/var/log/sipban/sipban.log"
ENDLINE

/usr/local/bin/sipban.pl >> /var/log/sipban/sipban_daemon.log 2>&1
