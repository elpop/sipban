#!/usr/bin/perl
#===================================================================#
# Program => sipban.pl (In Perl 5.0)                  version 0.0.1 #
#===================================================================#
# Autor         => Fernando "El Pop" Romo        (pop@cofradia.org) #
# Creation date => 07/jun/2019                                      #
#-------------------------------------------------------------------#
# Info => This program is a server who make a connection with a     #
#         asterisk server trough the TCP port 5038,take secrity     #
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
my $iptd = "$ipt -t filter -D sipban-udp -j RETURN";
my $ipta = "$ipt -t filter -A sipban-udp -j RETURN";

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

tie %ready, 'Tie::RefHash';
my $event_str = "";

# Flags to connect to Asterisk
my $manager_connect_time = 0;
my $manager_connect_flag = 1;

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
           if (exists($ban_ip{$control->[1]})) {
               $outbuffer{$client} .= "$control->[1] => $ban_ip{$control->[1]}\n";
           }
           else {
               $outbuffer{$client} .= "No hay información de $control->[1]\n";
           }
        }
        else {
            foreach my $ip (sort keys %ban_ip) {
                $outbuffer{$client} .= "$ip\n";
            }
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
        "invalidaccountid" => sub {
            my $packet_content_ref = shift;
            my ($service)    = $$packet_content_ref =~ /Service\:\s(.*?)\n/isx;
            my ($account_id) = $$packet_content_ref =~ /AccountID\:\s(.*?)\n/isx;
            my ($remote_ip)  = $$packet_content_ref =~ /RemoteAddress\:\sIPV4\/UDP\/(.*?)\/.*?\n/isx;
            if ($service eq 'PJSIP') {
                unless( exists($ban_ip{"$remote_ip"}) ) {
                    $ban_ip{$remote_ip} = time();
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
        "invalidpassword" => sub {
        },
    }, # Event
);

sub Iptables_Block {
    my $ip = shift;
    # /sbin/iptables -t filter -D sipban-udp -j RETURN
    # /sbin/iptables -t filter -A sipban-udp -s ${@%:*} -j REJECT --reject-with icmp-port-unreachable
    # /sbin/iptables -t filter -D sipban-udp -j RETURN
    my $rv = qx($iptd);
    $rv = qx($ipt -t filter -A $Config{'iptables.chain'} -s $ip -j $Config{'iptables.rule'});
    $rv = qx($ipta);
    print "BLOCK => $ip\n";
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

#-----------------------------------------------#
#  Function: Manager_Login                      #
#-----------------------------------------------#
# Objetive: Send Login Action to Asterisk API   #
#   Params: none                                #
#    Usage:                                     #
#          Manager_Login();                     #
#-----------------------------------------------#

sub Manager_Login {
    my $command  = "Action: login\r\n";
    $command .= "Username: $Config{'ami.user'}\r\n";
    $command .= "Secret: $Config{'ami.pass'}\r\n";
    $command .= "Events: on\r\n\r\n";
    Send_To_Asterisk(\$command);
}

#--------------------------------------------------#
# Function: Connect_To_Asterisk()                  #
#--------------------------------------------------#
# Objetive: connect program with asterisk manager  #
#   Params: None                                   #
#    Usage:                                        #
#          Connect_To_Asterisk();                  #
#--------------------------------------------------#

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

#--------------------------------------------------------#
# Function: Send_To_Asterisk([message])                  #
#--------------------------------------------------------#
# Objetive: Send  message to Asterik manager             #
#   Params: message, socket_handler                      #
#    Usage:                                              #
#          Send_To_Asterisk($message,$socket)            #
#--------------------------------------------------------#

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

#-------------------------------------------------------#
#  Fuction: Trim([var|array])                           #
#-------------------------------------------------------#
# Objetive: Take out blank spaces in the rigth and left #
#           of the field                                #
#   Params: one string or array                         #
#    Usage:                                             #
#          $sample = Trim(" vs ");                      #
#          $sample = Trim($foo);                        #
#          @sample = Trim(@data);                       #
#-------------------------------------------------------#

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
            $outbuffer{$client} .= "\n>";
       } else {
            $outbuffer{$client} = '>';
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
           $event = lc($event);
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

#---------------------------------------------------------#
#  Function: Clean_Connection([TCP handler])              #
#---------------------------------------------------------#
# Objetive: Close client TCP connection                   #
#   Params: [TCP handler]                                 #
#    Usage:                                               #
#          Clean_Connection($client_handler);             #
#---------------------------------------------------------#

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

#$/="\0";

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
            $outbuffer{$client} = "\nSipban (1.0)\n\n>";
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
