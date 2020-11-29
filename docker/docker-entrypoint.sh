#!/bin/bash

if [ $IPTABLES_RULE = "REJECT" ]; then
  rule="REJECT --reject-with icmp-port-unreachable"
if [ $IPTABLES_RULE = "DROP" ]; then
 rule="DROP"
fi

cat > /etc/sipban.conf <<ENDLINE
# SipBan Configuration File

# Parameters to connect to Asterisk AMI
[ami]
port = "${AMI_PORT}"
user = "${AMI_USER}"
pass = "${AMI_PASS}"
host = "${AMI_HOST}"
ping = ${AMI_PING}

# Port to send commands
[control]
port = "${SIPBAN_PORT}"

# Timers
[timer]
ban = ${TIMER_BAN}

#Iptables rules actions config
[iptables]
path  = "/sbin/"
chain = "${IPTABLES_CHAIN}"
rule  = ${rule}
white_list = "/etc/sipban/sipban.wl"
dump = "/etc/sipban/sipban.dump"

# Log file
[log]
file = "/var/log/sipban/sipban.log"
ENDLINE

/usr/local/bin/sipban.pl >> /var/log/sipban/sipban_daemon.log 2>&1
