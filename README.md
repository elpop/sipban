# SIPban

## Description

Program to stop SIP scanning attacks using live monitoring of the Asterisk AMI security Events and use iptables and ipset to block remote ip address.

The program use AMI (Asterisk manager Interface, with the security profile, obtain events related to SIP authorization on PJSIP and SIP channels.

Tested with Asterisk version 16.3.0 - 22.1.0 (C) 1999 - 2024, Digium, Inc. and others.
    
## Install
   
The service use iptables, you need the "**root**" user of your system

1. Download file
  
    ```
    git clone https://github.com/elpop/sipban.git
    ```  

2. Install dependecies:
         
    a) Ubuntu/Debian
         
    ```
    sudo apt-get install ipset libproc-pid-file-perl libconfig-simple-perl libnet-whois-ip-perl libtime-hires-perl libtie-cache-perl
    ```
         
    b) Redhat/CentOS/Fedora
    
    ```     
    sudo dnf install ipset perl-Proc-PID-File perl-Config-Simple perl-Net-Whois-IP perl-Time-HiRes perl-Tie-Cache
    ```
         
3. Copy configuration files

    ```      
     cd sipban
     cp sipban.pl /usr/local/bin/.
     cp etc/sipban.conf /etc/.
     cp etc/sipban.wl /etc/.
    ```
    
4. Edit and add **/etc/asterisk/manager.conf** acording our sample on **sipban/etc/asterisk/manager.conf**
         
    Use "**asterisk -rx'manager reload'**" after change the manager configuration file.
         
5. Install the launch scripts
      
    a) for init.d 
    
    ```     
    cp etc/init.d/sipban /etc/init.d/.
    chkconfig --level 345 sipban on
    /etc/init.d/sipban start
    ```
                    
    b) for systemd
    
    ```     
    cp etc/systemd/system/sipban.service /etc/systemd/system/.
    systemctl enable sipban
    service sipban start
    ```
    
## Configure

1. In the file **/etc/asterisk/manager.conf** we put this configuration:

    ```
    [general]
    enabled = yes
    
    port = 5038
    bindaddr = 127.0.0.1
    
    [sipban]
    secret = getout
    writetimeout = 100000
    read = security
    write = system,command
    ```

2. The **/etc/sipban.conf** contains the parameters of the service:

    ```   
    # SipBan Configuration File
    
    # Parameters to connect to Asterisk AMI
    [ami]
    port = "5038"
    user = "sipban"
    pass = "getout"
    host = "127.0.0.1"
    ping = 60
    
    # Port to send commands
    [control]
    port = "4451"
    address = "127.0.0.1"
    
    #Iptables rules actions config
    [iptables]
    path       = "/sbin/"
    chain      = "sipban"
    # to block udp port 5060, you can block all but test
    # with caution to avoid lost total access to your system.
    #scope = "-p udp --dport 5060"
    scope      = ""
    #rule  = "REJECT --reject-with icmp-port-unreachable"
    rule       = "DROP"
    white_list = "/etc/sipban.wl"
    interface  = "eno1"
    
    [ipset]
    path     = "/sbin/"
    set_name = "sipban"
    dump     = "/etc/sipban.dump"
    # week
    timeout  = 604800
    # day
    #timeout  = 86400 
    
    [log]
    file = "/var/log/sipban.log"
    
    [flood]
    # Originaly, the value of "count" was 30, but we detect cleaver attacks
    # using sipvicious (https://github.com/EnableSecurity/sipvicious).
    # in this new kind of attack, send burst of flood, wait and send again
    # avoiding the interval analysis. Adjust depending your use case.
    count=5
    interval=10
    ```
    
    The file is sefl explanatory. only take in count the "timer->ban" parameter are seconds (default 86400 = 1 day).
   
    The "iptables->rule" option is how iptables respond to the attack, you can choose "REJECT" or "DROP"

    The flood section will block based on the number (count) of invites received of a period of (inteval) seconds. In the default configuration if there are 30 SIP Invites from the same IP on the course of 30 seconds it will block the offender.
   
3. The White List is on **/etc/sipban.wl**. This file contains the ip address you don't want to block (one ip per line). You can change the location modify the sipban configuration file.
   
4. The sipban.dump file is a temp one to save the ip's and ban timers in case of mantinance.
   
5. You can reach via Telnet with the port 4451 (you can change in the "control->port" pararmeter).
        
## Operation

1. The service are fully automatic, but you can control through the port 4451 (or another defined on **/etc/sipban.conf**), v.g.:
   
    ```   
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
    save                 => Dump the blocked IP's
    restore              => If exists a dump file restore the rules from it
    uptime               => show the program uptime
    whois                => show the WHOIS info of a given ip
    wl                   => show white list ip address
    exit/quit            => exit console session
        
    sipban>
    ```
    
2. The log files reside on the file "**/var/log/sipban.log**"
   
    ```
    [root@pbx ~]# tail -f /var/log/sipban.log 
    [2024-12-02 10:40:25] SipBan Start
    [2024-12-02 10:40:25] WHITE LIST => 127.0.0.1
    [2024-12-02 10:40:25] WHITE LIST => 10.88.1.11
    [2024-12-02 10:40:25] WHITE LIST => 10.88.1.1
    [2024-12-02 10:40:25] WHITE LIST => 10.64.12.1
    [2024-12-02 10:40:25] WHITE LIST => 10.64.12.10
    [2024-12-02 10:40:25] IPSET => set sipban created
    [2024-12-02 10:40:25] CHAIN => sipban created
    [2024-12-02 10:40:31] BLOCK => 54.39.137.81 (Invalid Account)
    [2024-12-02 10:53:46] BLOCK => 87.98.251.101 (Invalid Account)
    [2024-12-02 10:56:42] BLOCK => 185.243.5.55 (Invalid Account)
    [2024-12-02 11:20:20] BLOCK => 206.168.34.198 (Invalid Account)
    [2024-12-02 12:25:48] BLOCK => 94.23.148.30 (Invalid Account)
    ...   
    ```

3. You can check the iptables rules with "**sipban_admin.bash -l**"
   
    ```
    [root@pbx ~]# sipban_admin.bash -l

    Name: sipban
    Type: hash:ip
    Revision: 5
    Header: family inet hashsize 4096 maxelem 65536 timeout 604800 bucketsize 12 initval 0x285783a9
    Size in memory: 3536
    References: 1
    Number of entries: 6
    Members:
    23.95.39.90 timeout 596479
    94.23.145.155 timeout 596479
    84.32.32.134 timeout 596479
    154.212.141.253 timeout 596479
    209.141.54.234 timeout 596479
    172.168.40.246 timeout 596479
    ```

## Docker

Our friend Federico Pereira (lord.basex@gmail.com), make the docker image of SipBan, the instructions are on the README.md on the docker directory.


## To-do

   - IPv6 support
   - IP Class blocking

## Author

   Fernando Romo (pop@cofradia.org)

## License
     
```
GNU GENERAL PUBLIC LICENSE Version 3
https://www.gnu.org/licenses/gpl-3.0.en.html
See LICENSE.txt
```

## Sponsor the project

Please [sponsor this project](https://github.com/sponsors/elpop), to pay my high debt on credit cards :)
