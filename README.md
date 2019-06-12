SIPban

Abstract

   Program to stop SIP scanning attacks using live monitoring of the Asterisk AMI security Events and use iptables to block remote ip address.

Description

   The program use AMI (Asterisk manager Interface)i, with the security profile, obtain events related to SIP authorization on PJSIP and SIP channels.

   In the file /etc/asterisk/manager.conf we put this configuration:

      [general]
      enabled = yes

      port = 5038
      bindaddr = 127.0.0.1

      [sipban]
      secret = getout
      writetimeout = 100000
      read = security
      write = system,command
   
   the /etc/sipban.conf contains the parameters of the service:
   
       # SipBan Configuration File

       # Parameters to connect to Asterisk AMI
       [ami]
       port = "5038"
       user = "sipban"
       pass = "getout"
       host = "127.0.0.1"
       ping = 600

       # Port to send commands
       [control]
       port = "4451"

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
       file = "/var/log/sipban.log"

   The file is sefl explanatory. only take in count the "timer->ban" parameter are seconds (default 86400 = 1 day).
   
   The "iptables->rule" option is how iptables respond to the attack, you can choose "REJECT" or "DROP"
   
   The White List is on /etc/sipban.wl. This file contains the ip address you don't want to block (one ip per line). You can change the location modify the sipban configuration file.
   
   The sipban.dump file is a temp one to save the ip's and ban timers in case of mantinance.
   
   You can reach via Telnet with the port 4451 (you can change in the "control->port" pararmeter).
    
Install
   
   the service use iptables, you need the "root" user of your system.
   
      1) download file
      
         git clone https://github.com/elpop/sipban.git
         
      2) Copy configuration files
      
         cd sipban
         cp sipban.pl /usr/local/bin/.
         cp etc/sipban.conf /etc/.
         cp etc/sipban.wl /etc/.
       
      3) Edit and add /etc/asterisk/manager.conf acording our sample on sipban/etc/asterisk/manager.conf
         
         use " asterisk -rx'manager reload' " after change the manager configuration file
         
      4) install the launch scripts
      
         a) for init.d 
         
            cp etc/init.d/sipban /etc/init.d/.
            chkconfig --level 345 sipban on
            /etc/init.d/sipban start
                    
         b) for systemd
         
            cp etc/systemd/system/sipban.service /etc/systemd/system/.
            systemctl enable sipban
            service sipban start
            
Operation

   The service are fully automatic, but you can control through the port 4451 (or another defined on /etc/sipban.conf), v.g.:
   
         [root@pbx ~]# telnet localhost 4451
         Trying ::1...
         telnet: connect to address ::1: Connection refused
         Trying 127.0.0.1...
         Connected to localhost.
         Escape character is '^]'.

         Sipban
         use 'help' for more commands
         sipban>
         
         
         sipban>help

         Commands:

         block                => List blocked ip address
         block {ip address}   => block ip address
         unblock [ip address] => unblock ip address
         flush                => Dump the blocked IP's and clear rules on chain sipban-udp
         restore              => If exists a dump file restore the rules from it
         ping                 => Send ping to Asterisk AMI
         uptime               => show the program uptime
         wl                   => show white list ip address
         exit/quit            => exit console session

         sipban>

   The log files reside on the file "/var/log/sipban.log"
   
         [root@pbx ~]# tail -f /var/log/sipban.log 
         [2019-06-12 12:01:50] SipBan Start
         [2019-06-12 12:01:50] WHITE LIST => 127.0.0.1
         [2019-06-12 12:01:55] BLOCK => 221.121.138.167
         [2019-06-12 12:01:59] BLOCK => 77.247.110.158
         [2019-06-12 12:02:01] BLOCK => 102.165.39.82
         [2019-06-12 12:02:06] BLOCK => 102.165.32.36
         [2019-06-12 12:02:07] BLOCK => 102.165.49.34
         [2019-06-12 12:02:08] BLOCK => 77.247.109.243
         ...   

   You can check the iptables rules with "iptables -S sipban-udp"
   
         [root@pbx ~]# iptables -S sipban-udp
         -N sipban-udp
         -A sipban-udp -s 221.121.138.167/32 -j DROP 
         -A sipban-udp -s 77.247.110.158/32 -j DROP 
         -A sipban-udp -s 102.165.39.82/32 -j DROP 
         -A sipban-udp -s 102.165.32.36/32 -j DROP 
         -A sipban-udp -s 102.165.49.34/32 -j DROP 
         -A sipban-udp -s 77.247.109.243/32 -j DROP 
         ...
         -A sipban-udp -j RETURN 

 
   
   
   
   
   
