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
   
   You can reach via Telnet with the port 4451 (you can change in the "control-port" pararmeter).
    
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
            
         
            

   
   
   
   
   
   
   
