#!/usr/bin/perl
#===================================================================#
# Program => sipban.pl (In Perl 5.0)                  version 0.0.1 #
#===================================================================#
# Autor         => Fernando "El Pop" Romo        (pop@cofradia.org) #
# Creation date => 07/jun/2019                                      #
#-------------------------------------------------------------------#
# Info => This program is a server who make a connection with a     #
#         asterisk server trough the TCP port 5038,take security    #
#         Events and use iptables to block suspicious SIP registers #
#-------------------------------------------------------------------#
# This code are released under the GPL 3.0 License. Any change must #
# be report to the authors                                          #
#              (c) 2019 - Fernando Romo / Incuvox                   #
#===================================================================#
use strict;
use POSIX;
use IO::Socket;
use IO::Select;
use Socket;
use Fcntl;
use Tie::RefHash;
use Time::HiRes qw(usleep);
use Proc::PID::File;
use File::Basename;
use Config::Simple;
#use IPTables::ChainMgr;

my %Config;
Config::Simple->import_from('/etc/sipban.conf', \%Config) or die Config::Simple->error();

# check PID File
die "Already runnig" if Proc::PID::File->running( dir=>"/tmp/", name => basename("$0",".pl") );

#--------------------#
# Control Parameters #
#--------------------#

# Timers Info
my $Start_Time = time();
my $Ping_Time  = $Start_Time + $Config{'ami.ping'};

# Socket handlers
my $asterisk_handler;
my $asterisk_select;
my $asterisk_client;

# signal traps
$SIG{PIPE} = 'IGNORE';
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = 'Terminate';

# Iptables commands
my $ipt = "$Config{'iptables.path'}" . 'iptables';

# Open Socket connection to accept clients requests
my $server = IO::Socket::INET->new(LocalPort => "$Config{'control.port'}",
                                   Listen    => 10,
                                   ReuseAddr => 1 )
  or die "Can't make server socket: $@\n";
Nonblock($server);
my $select = IO::Select->new($server);

# begin with empty buffers
my %inbuffer     = ();
my %outbuffer    = ();
my %ready        = ();
my %sessions     = ();
my %ban_ip       = ();
my %white_list   = ();

tie %ready, 'Tie::RefHash';
my $event_str = "";

# Flags to connect to Asterisk
my $manager_connect_time = 0;
my $manager_connect_flag = 1;

# Help
my $HELP = "\nCommands:\n\n";
$HELP .= "ban                => List blocked ip address\n";
$HELP .= "ban {ip address}   => block ip address\n";
$HELP .= "unban \[ip address\] => unblock ip address\n";
$HELP .= "flush              => Dump the blocked IP's and clear rules on chain $Config{'iptables.chain'}\n";
$HELP .= "restore            => If exists a dump file restore the rules from it\n";
$HELP .= "ping               => Send ping to Asterisk AMI\n";
$HELP .= "uptime             => show the program uptime\n";
$HELP .= "wl                 => show white list ip address\n";
$HELP .= "exit/quit          => exit console session\n";

# open log file
open(LOG, ">> $Config{'log.file'}") or die;
LOG->autoflush(1);

print LOG Time_Stamp() . " SipBan Start\n";

#----------------------------------------------------------------------------------------------
# [Developer Note]: the process of each client request is declared in the %Client_Handler
#                   Hash and use references for speed operations in the event detection cycle.
#----------------------------------------------------------------------------------------------

my %Client_Handler = (
    "ban" => sub {
        my $client = shift;
        my $control = shift;
        $outbuffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip) = $control->[1] =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if ($ip) {
                if (exists($ban_ip{$ip})) {
                    $outbuffer{$client} .= "$ip previously blocked\n";
                }
                else {
                    $ban_ip{$ip} = time() + $Config{'timer.ban'};
                    Iptables_Block($ip);                  
                    $outbuffer{$client} .= "$ip block\n";
                }
            }
            else {
                $outbuffer{$client} .= "$ip don't seems like a valid address\n";
            }
        }
        else {
            foreach my $ip (sort keys %ban_ip) {
                $outbuffer{$client} .= "$ip\n";
            }
        }
    },
    "unban" => sub {
        my $client = shift;
        my $control = shift;
        $outbuffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip) = $control->[1] =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if ($ip) {
                if (exists($ban_ip{$ip})) {
                    Iptables_UnBlock($ip);
                    delete $ban_ip{$ip};
                    $outbuffer{$client} .= "$ip unblocked\n";
                }
                else {
                    $outbuffer{$client} .= "$ip is not previously blocked\n";
                }
            }
            else {
                $outbuffer{$client} .= "$ip don't seems like a valid address\n";
            }
        }
        else {
            $outbuffer{$client} .= "ip address missing\n";
        }
    },
    "flush" => sub {
        my $client = shift;
        Dump_Ban_IPs();
        Iptables_Erase_Chain();
        Iptables_Create_Chain();
        $outbuffer{$client} .= "iptables rules from chain $Config{'iptables.chain'} removed\n";
    },
    "restore" => sub {
        my $client = shift;
        Restore_Rules($client);
    },
    "help" => sub {
        my $client = shift;
        $outbuffer{$client} .= $HELP;
    },
    "ping" => sub {
        my $client = shift;
        print LOG Time_Stamp() . " Ping\n";
        Send_To_Asterisk(\"Action: Ping\r\n\r\n");
        $outbuffer{$client} .= "Ping sent\n";
    },
    "uptime" => sub {
        my $client = shift;
        $outbuffer{$client} .= 'Uptime ' . Convert_To_Time(time() - $Start_Time). "\n";
    },    
    "wl" => sub {
        my $client = shift;
        $outbuffer{$client} .= '';
        foreach my $ip (sort keys %white_list) {
            $outbuffer{$client} .= "$ip\n";
        }
    },
    "quit" => sub {
        my $client = shift;
        delete $inbuffer{$client};
        delete $outbuffer{$client};
        delete $ready{$client};
        delete $sessions{$client};
        $select->remove($client);
        close($client);
    }, 
);
#----------------------------------------------------------------
# [Pop] Developer Note: I declare the "exit" command Out of the
# initial %Client_Handler Hash declaration to avoid perl compiler 
# errors because i try to invoque a non declare hash into the 
# same hash :P
# 
# The trick is receive the "exit" command and call the same 
# rutine of the "quit" event.
#----------------------------------------------------------------
$Client_Handler{exit} = (sub {
    my $client = shift;
    $Client_Handler{quit}->($client);
});

#--------------------------------------------------------------------------------------
# [Developer Note]: the process of each packet comming from the asteris manager (AMI),
#                   is declared in the %AMI_Handler Hash and use references for
#                   speed operations in the event detection cycle.
#--------------------------------------------------------------------------------------

my %AMI_Handler = ( 
    "Event" => {
        #-----------------------------
        # Event: ChallengeResponseFailed
        # Privilege: security,all
        # EventTV: 2019-06-07T21:19:53.973+0000
        # Severity: Error
        # Service: PJSIP
        # EventVersion: 1
        # AccountID: 5500
        # SessionID: 99260NzkzMWE4ZDkyMGE5ZWJlN2U0YjA4NGJkNmFiM2JiMmU
        # LocalAddress: IPV4/UDP/10.211.55.8/5060
        # RemoteAddress: IPV4/UDP/10.211.55.2/49169
        # Challenge: 1559942393/fa9af96cd0edc616034019384a5365d9
        # Response: d9a4942821c8a4148ebfb7b88ce7ae3e
        # ExpectedResponse: 
        #-----------------------------

        #-----------------------------
        # Event: InvalidAccountID
        # Privilege: security,all
        # EventTV: 2019-06-07T21:25:59.559+0000
        # Severity: Error
        # Service: PJSIP
        # EventVersion: 1
        # AccountID: 55001
        # SessionID: 99260YTExOWI2Y2NjZTVhODQ4NTVmMmZjMDc1MWUwMzY3MTM
        # LocalAddress: IPV4/UDP/10.211.55.8/5060
        # RemoteAddress: IPV4/UDP/10.211.55.2/59977
        #-----------------------------
        "InvalidAccountID" => sub {
            my $packet_content_ref = shift;
            my ($service)    = $$packet_content_ref =~ /Service\:\s(.*?)\n/isx;
            my ($account_id) = $$packet_content_ref =~ /AccountID\:\s(.*?)\n/isx;
            my ($remote_ip)  = $$packet_content_ref =~ /RemoteAddress\:\sIPV4\/UDP\/(.*?)\/.*?\n/isx;
            if ( ($service eq 'PJSIP') || ($service eq 'SIP') ) {
                unless( exists($ban_ip{"$remote_ip"}) ) {
                    $ban_ip{$remote_ip} = time() + $Config{'timer.ban'};
                    Iptables_Block($remote_ip);
                }
            }
        },
        #-----------------------------
        # Event: InvalidPassword
        # Privilege: security,all
        # EventTV: 2019-06-07T21:17:59.819+0000
        # Severity: Error
        # Service: SIP
        # EventVersion: 2
        # AccountID: 5500
        # SessionID: 0x7f8db400d860
        # LocalAddress: IPV4/UDP/10.211.55.8/5060
        # RemoteAddress: IPV4/UDP/10.211.55.2/52551
        # Challenge: 79cca43d
        # ReceivedChallenge: 79cca43d
        # ReceivedHash: 91801011d87fe17fca4aca4893f9920d
        #-----------------------------
        "InvalidPassword" => sub {
            my $packet_content_ref = shift;
            my ($service)    = $$packet_content_ref =~ /Service\:\s(.*?)\n/isx;
            my ($account_id) = $$packet_content_ref =~ /AccountID\:\s(.*?)\n/isx;
            my ($remote_ip)  = $$packet_content_ref =~ /RemoteAddress\:\sIPV4\/UDP\/(.*?)\/.*?\n/isx;
            if ( ($service eq 'PJSIP') || ($service eq 'SIP') ) {
                unless( exists($ban_ip{"$remote_ip"}) ) {
                    $ban_ip{$remote_ip} = time() + $Config{'timer.ban'};
                    Iptables_Block($remote_ip);
                }
            }
        },
    }, # Event
    "Response" => {
        "Success" => sub {
            my $packet_content_ref = shift;
            if ($$packet_content_ref =~ /Ping\:\sPong/) {
               # print LOG Time_Stamp() . " Pong\n";               
            }
        
        }
    } # Response
);

sub Time_Stamp {
    my ($sec, $min, $hour, $day,$month,$year) = (localtime( time() ))[0,1,2,3,4,5];
    $year = $year + 1900;
    $month++;
    return sprintf("\[%04d-%02d-%02d %02d:%02d:%02d\]",$year,$month,$day,$hour,$min,$sec);
}

sub Convert_To_Time {
    my $time = shift;
    my $days = int($time / 86400);
    my $aux = $time % 86400;
    my $hours = int($aux / 3600);
       $aux = $aux % 3600;
    my $minutes = int($aux / 60);
    my $seconds = $time % 60;
    my $result = "";
    if ($days == 1) {
        $result = "$days day ";
    }
    elsif ($days > 1) {
        $result = "$days days ";
    }
    $result .= sprintf("%02d\:%02d\:%02d",$hours,$minutes,$seconds);
    return $result;
}

sub Dump_Ban_IPs {
    open DUMP, "> $Config{'iptables.dump'}" || die "Can\'t open file\n";
    print LOG Time_Stamp() . " DUMP => $Config{'iptables.chain'}\n";
    print DUMP '# '. Time_Stamp() . "\n";
    foreach my $ip (sort keys %ban_ip) {
        print DUMP "$ip\n";
    }    
    close (DUMP);
}

sub Restore_Rules {
    my $client = shift;
    if (-e $Config{'iptables.dump'}) {
        open DUMP, "< $Config{'iptables.dump'}" || die "Can\'t open file\n";
        print LOG Time_Stamp() . " RESTORE RULES => $Config{'iptables.chain'}\n";
        $outbuffer{$client} .= "Restore rules $Config{'iptables.chain'}\n"; 
        while(<DUMP>) { # Read records
            chomp;
            my ($ip) = $_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if ($ip) {
                unless( exists($ban_ip{"$ip"}) ) {
                    $ban_ip{$ip} = time() + $Config{'timer.ban'};
                    Iptables_Block($ip);
                    $outbuffer{$client} .= "$ip\n";
                }
            }
        }
        $outbuffer{$client} .= "End restore rules\n"; 
        close (DUMP);
        unlink $Config{'iptables.dump'} or warn "Could not unlink $Config{'iptables.dump'}: $!";
    }
    else {
        $outbuffer{$client} .= "no dump file to restore rules\n";  
    }
}

sub Iptables_Create_Chain {
    %ban_ip = ();
    # /sbin/iptables -t filter -N sipban-udp
    # /sbin/iptables -t filter -I INPUT 1 -p udp --dport 5060 -j sipban-udp
    # /sbin/iptables -t filter -A sipban-udp -j RETURN
    my $rv = qx($ipt -t filter -N $Config{'iptables.chain'});
    $rv = qx($ipt -t filter -I INPUT 1 -p udp --dport 5060 -j $Config{'iptables.chain'});
    $rv = qx($ipt -t filter -A $Config{'iptables.chain'} -j RETURN);
    print LOG Time_Stamp() . " CHAIN => $Config{'iptables.chain'} created\n";
}

sub Iptables_Erase_Chain {
    foreach my $ip (sort keys %ban_ip) {
        Iptables_UnBlock($ip);
    }
    %ban_ip = ();
    ## /sbin/iptables -t filter -D INPUT 1 -p udp --dport 5060 -j sipban-udp
    # /sbin/iptables -t filter -D INPUT 1
    # /sbin/iptables -t filter -F sipban-udp
    # /sbin/iptables -t filter -X sipban-udp
    my $rv = qx($ipt -t filter -D INPUT 1);
    $rv = qx($ipt -t filter -F $Config{'iptables.chain'});
    $rv = qx($ipt -t filter -X $Config{'iptables.chain'});
    print LOG Time_Stamp() . " CHAIN => $Config{'iptables.chain'} erased\n";
}

sub Iptables_Block {
    my $ip = shift;
    unless( exists($white_list{$ip}) ) {
        # /sbin/iptables -t filter -D sipban-udp -j RETURN
        # /sbin/iptables -t filter -A sipban-udp -s 88.88.88.88 -j REJECT --reject-with icmp-port-unreachable
        # /sbin/iptables -t filter -A sipban-udp -j RETURN
        my $rv = qx($ipt -t filter -D sipban-udp -j RETURN);
        $rv = qx($ipt -t filter -A $Config{'iptables.chain'} -s $ip -j $Config{'iptables.rule'});
        $rv = qx($ipt -t filter -A sipban-udp -j RETURN);
        print LOG Time_Stamp() . " BLOCK => $ip\n";
    }
}

sub Iptables_UnBlock {
    my $ip = shift;
    # /sbin/iptables -D sipban-udp -s 88.88.88.88/32 -j REJECT
    my $rv = qx($ipt -D $Config{'iptables.chain'} -s $ip -j $Config{'iptables.rule'});
    print LOG Time_Stamp() . " UNBLOCK => $ip\n";
}

sub Terminate {
    my $client;
    # Clean up connections
    foreach $client (keys %sessions) {
        $select->remove($client);
        close($client);
    }
    close($server);                   # destroy socket handler
    close($asterisk_handler);         # destroy asterisk manager conection
    print LOG Time_Stamp() . " SipBan Stop\n";
    close(LOG);
    exit(0);                          # Exit without error
}

sub Nonblock {
    my $socket = shift;
    my $flags;
    
    $flags = fcntl($socket, F_GETFL, 0)
            or die "Can't get flags for socket: $!\n";
    fcntl($socket, F_SETFL, $flags | O_NONBLOCK)
            or die "Can't make socket nonblocking: $!\n";
}

sub Manager_Login {
    my $command  = "Action: login\r\n";
    $command .= "Username: $Config{'ami.user'}\r\n";
    $command .= "Secret: $Config{'ami.pass'}\r\n";
    $command .= "Events: on\r\n\r\n";
    Send_To_Asterisk(\$command);
}

sub Connect_To_Asterisk {
    my $host = shift;
    $asterisk_handler = new IO::Socket::INET->new( PeerAddr  => "$host",
                                                   PeerPort  => $Config{'ami.port'},
                                                   Proto     => "tcp",
                                                   ReuseAddr => 1,
                                                   Type      => SOCK_STREAM );
    if ($asterisk_handler) {
        $asterisk_handler->autoflush(1);
        Nonblock($asterisk_handler);
        $select->add($asterisk_handler);
        $manager_connect_time = time;
        return 0;
    } 
    else {
    	return 1;
    }
}

sub Send_To_Asterisk {
    my $command_ref = shift;
    
    unless ($$command_ref eq "" && $manager_connect_flag == 1) {
        #--------------------------------------------------------------------------------#
  	    # Developer Note: in some cases, the API Manager sufer of a requets override and #
  	    #                 is necesary put a little time wait between requests.           #
        #--------------------------------------------------------------------------------#
        # usleep 200_000;
        # if the socket exists send data, if not, turn on reconnection flag
        unless($asterisk_handler eq "") {
            my $rv;
            # use eval to isolate the send command in case of failure and continue the main process
            eval { $rv = $asterisk_handler->send($$command_ref, 0) };
            unless (defined $rv) {
                # if send fails, turn on reconnection flag
                $manager_connect_flag = 1;
            }
        } 
        else {
            $manager_connect_flag = 1;
        }
    }
}

sub Trim {
    my @out = @_;
    
    for (@out) {
         s/^\s+//g;
         s/\s+$//g;
    }
    return wantarray ? @out : $out[0];
}                	        

#---------------------------------------------------------#
#  Function: Handle_Clients([Client TCP handler])         #
#---------------------------------------------------------#
# Objetive: Take the requests of client programs and      #
#           interface with Asterisk manager               #
#   Params: [client TCP handler]                          #
#    Usage:                                               #
#          Handle_Clients($client);                       #
#---------------------------------------------------------#

sub Handle_Clients {
    # requests are in $ready{$client}
    # send output to $outbuffer{$client}
    my $client = shift;
    my $request;

    foreach $request (@{$ready{$client}}) {
       $request =~ s/\r|\n//g;
       if ($request) {
           my @control = split (/\s+/, Trim($request));
           if (exists($Client_Handler{$control[0]})) {
               $Client_Handler{$control[0]}->($client,\@control); 
           } 
           else {
               $outbuffer{$client} .= "Invalid command"; 
           }
       }
       if ($outbuffer{$client}) {
            $outbuffer{$client} .= "\nsipban>";
       } else {
            $outbuffer{$client} = 'sipban>';
       }
    }
    delete $ready{$client};
}

#---------------------------------------------------------#
#  Function: Handle_Events([Asterisk TCP handler])        #
#---------------------------------------------------------#
# Objetive: Take the requests of Asterisk and manipulate  #
#           the asterisk Manager events.                  #
#   Params: [Asterisk TCP handler]                        #
#    Usage:                                               #
#          Handle_Events($asterisk_handler);              #
#---------------------------------------------------------#

sub Handle_AMI {
    # requests are in $ready{$client}
    # send output to $outbuffer{$client}
    my $client = shift;
    my $request;
    my @packet = ();

    foreach $request (@{$ready{$client}}) {
        $event_str .= $request if ($request);
    }
    if ($event_str =~ /\r\n\r\n/) {
       # put each packet in separate area
       @packet = $event_str =~ /(?:Action|Event|Message|Response).*?\r\n\r\n/isxg;
       # process each individual packet 
       foreach my $packet_content (@packet) {
           $packet_content =~ s/\r//g;
           # Analyze each packet header and process according
           my ($ami_action, $event) = $packet_content =~ /^(.*?):\s(.*?)\n/isx;
           # $event = lc($event);
           if (exists($AMI_Handler{$ami_action}{$event})) {
               $AMI_Handler{$ami_action}{$event}->(\$packet_content);
           }              
       }       
       # if exists a remainder incomplet event, keep it to the next round  
       my $last_pos = rindex($event_str,"\r\n\r\n");
       $last_pos = $last_pos + 4;
       my $len = length($event_str);
       if ($len > $last_pos) {
           $event_str = substr($event_str,$last_pos);
       } 
       else {
           $event_str = "";
       }
    }
    delete $ready{$client};
}

sub Clean_Connection {
    my $client_session = shift;

    # Delete working buffers
    delete $inbuffer{$client_session};
    delete $outbuffer{$client_session};
    delete $ready{$client_session};
    delete $sessions{$client_session};

    # Check if the connection to Asterisk Die and turn the reconnection Flag
    if ($client_session eq $asterisk_handler) {
    	$manager_connect_flag =1;
    } 
    $select->remove($client_session);
    close($client_session);
}

#======================#
#      Main block      #
#======================#

# Load white list from file to hash %white_list
if (-e $Config{'iptables.white_list'}) {
    open WL, "< $Config{'iptables.white_list'}" || die "Can\'t open file\n";
    while(<WL>) { # Read records
        chomp;
        my ($ip) = $_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
        if ($ip) {
            $white_list{$_} = 1;
            print LOG Time_Stamp() . " WHITE LIST => $_\n";
        }
    }
    close (WL);
}

# Check if exists the chain name or else create one
my $rv = qx($ipt -S $Config{'iptables.chain'});
if ($rv =~ /No chain\/target\/match/) {
    Iptables_Create_Chain();
}
# search previous rules in the chain name
else {
    my $rule_time = $Start_Time + $Config{'timer.ban'};
    my @iptables_list = split("\n",$rv);
    foreach my $line (@iptables_list) {
        my ($ip) = $line =~ /-A\s$Config{'iptables.chain'}\s-s\s(.*?)\/.*?\s-j\s/;
        if ($ip) {
            $ban_ip{$ip} = $rule_time;
            print LOG Time_Stamp() . " BLOCKED => $ip\n";
        }
    }
    @iptables_list = ();
}

# Main Cycle

while (1) { # Main loop #
    my $client;
    my $rv;
    my $data;
    if ($manager_connect_flag) {
        $manager_connect_flag = Connect_To_Asterisk("$Config{'ami.host'}");
        unless ($manager_connect_flag) {
            Manager_Login();
        } 
    }
    
    # check for new information on the connections we have.
    # anything to read or accept?
    foreach $client ($select->can_read(1)) {
        if ($client == $server) {
            # accept a new connection
            $client = $server->accept();
            $select->add($client);
            Nonblock($client);
            $sessions{$client} = 1;
            $outbuffer{$client} = "\nSipban\nuse 'help' for more commands\nsipban>";
        } 
        else {
            # read data
            $data = '';
            eval { $rv   = $client->recv($data, POSIX::BUFSIZ, 0) };
            unless (defined($rv) && length $data) {
                # This would be the end of file, so close the client
                Clean_Connection($client);
                next;
            }
            $data =~ s/\0/\r\n/g;
            $inbuffer{$client} .= $data;
            # test whether the data in the buffer or the data we
            # just read means there is a complete request waiting
            # to be fulfilled.  If there is, set $ready{$client}
            # to the requests waiting to be fulfilled.
            while ($inbuffer{$client} =~ s/(.*\r\n)//) {
                push( @{$ready{$client}}, $1 );
            }
        }
    }
    
    # Any complete requests to process?
    foreach $client (keys %ready) {
        if ($client eq $asterisk_handler) {
            Handle_AMI($client);
        } 
        else {
            Handle_Clients($client);
        }
    }
    
    my $current_time = time();
    if ($current_time >= $Ping_Time) {
        $Ping_Time += $Config{'ami.ping'};
        # print LOG Time_Stamp() . " Ping\n";
        Send_To_Asterisk(\"Action: Ping\r\n\r\n");
    }

    # Buffers to flush?
    foreach $client ($select->can_write(1)) {
        # Skip this client if we have nothing to say
        next unless exists $outbuffer{$client};
        # Check if the socket exists before send
        ## if (defined(getpeername($client))) {
        unless($client eq "") {
            # use eval to isolate the send command in case of failure and continue the main process
            eval { $rv = $client->send($outbuffer{$client}, 0) };
            unless (defined $rv) {
                # Whine, but move on.
                warn "I was told I could write, but I can't.\n";
                next;
            }
            if ($rv == length $outbuffer{$client} ||
                $! == POSIX::EWOULDBLOCK) {
                substr($outbuffer{$client}, 0, $rv) = '';
                delete $outbuffer{$client} unless length $outbuffer{$client};
            } else {
                Clean_Connection($client);
                next;
            }
        } else {
            Clean_Connection($client);
            next;
	    }
    }
    
    # Out of band data?
    foreach $client ($select->has_exception(0)) {  # arg is timeout
        # Deal with out-of-band data here, if you want to.
    }
} # End of main loop

#------------- End of main block ----------