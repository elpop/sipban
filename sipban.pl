#!/usr/bin/perl
#======================================================================#
# Program => sipban_ipset.pl (In Perl 5.0)               version 1.0.0 #
#======================================================================#
# Autor => Fernando "El Pop" Romo                   (pop@cofradia.org) #
# Creation date => 07/jun/2019                                         #
#----------------------------------------------------------------------#
# Info => This program is a server who make a connection with a        #
#         asterisk server trough the TCP port 5038,take security       #
#         Events and use iptables to block suspicious SIP registers    #
#----------------------------------------------------------------------#
#        This code are released under the GPL 3.0 License.             #
#                                                                      #
#                  (c) 2019-2024 - Fernando Romo                       #
#                                                                      #
# This program is free software: you can redistribute it and/or modify #
# it under the terms of the GNU General Public License as published by #
# the Free Software Foundation, either version 3 of the License, or    #
# (at your option) any later version.                                  #
#                                                                      #
# This program is distributed in the hope that it will be useful, but  #
# WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU    #
# General Public License for more details.                             #
#                                                                      #
# You should have received a copy of the GNU General Public License    #
# along with this program. If not, see <https://www.gnu.org/licenses/> #
#======================================================================#
use strict;
use POSIX;
use IO::Socket;
use IO::Select;
use Socket;
use Fcntl;
use Net::Whois::IP qw(whoisip_query);
use Tie::RefHash;
use Time::HiRes qw(usleep);
use Proc::PID::File;
use File::Basename;
use Config::Simple;
use Tie::Cache;

my %cache = ();
tie %cache, 'Tie::Cache', 1000, { Debug => 0 };

if (defined($ARGV[0])) {
    if ($ARGV[0] eq "-d") {
        defined(my $pid = fork) or die "Can't Fork: $!";
        exit if $pid;
        setsid or die "Can't start a new session: $!";
    }
}

# check PID File
die "Already runnig" if Proc::PID::File->running( dir=>"/tmp/", name => basename("$0",".pl") );

my %Config;
Config::Simple->import_from('/etc/sipban.conf', \%Config) or die Config::Simple->error();

#--------------------#
# Control Parameters #
#--------------------#

# Timers Info
my $Start_Time = time();
my $Ping_Time  = $Start_Time + $Config{'ami.ping'};
# 9999-12-31 23:59:59 UTC this epoch could be higher, but is a nice date
my $max_epoch = 253402300799;
my $min_epoch = $max_epoch;

# Socket handlers
my $asterisk_handler;
my $asterisk_select;
my $asterisk_client;

# signal traps
$SIG{PIPE} = 'IGNORE';
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = 'Terminate';

my $ipt = "$Config{'iptables.path'}" . 'iptables'; # iptables command
my $ips = "$Config{'ipset.path'}" . 'ipset';       # ipset command

# Open Socket connection to accept clients requests
my $server = IO::Socket::INET->new(LocalPort => "$Config{'control.port'}",
                             LocalAddr => "$Config{'control.address'}",
                             Listen    => 10,
                             ReuseAddr => 1,
                             Blocking  => 0,
) or die "Can't make server socket: $@\n";

$server->blocking(0);

my $select = IO::Select->new($server);

# begin with empty buffers
my %in_buffer     = ();
my %out_buffer    = ();

my %sessions     = ();
my %ban_ip       = ();
my %white_list   = ();

tie %in_buffer, 'Tie::RefHash';
my $event_str = "";

# Flags to connect to Asterisk
my $manager_connect_time = 0;
my $manager_connect_flag = 1;

# Help
my $HELP = "\nCommands:\n\n";
$HELP .= "block                => List blocked ip address\n";
$HELP .= "block {ip address}   => block ip address\n";
$HELP .= "unblock \[ip address\] => unblock ip address\n";
$HELP .= "save                 => Dump the blocked IP's\n";
$HELP .= "restore              => If exists a dump file restore the rules from it\n";
$HELP .= "uptime               => show the program uptime\n";
$HELP .= "whois                => show the WHOIS info of a given ip\n";
$HELP .= "wl                   => show white list ip address\n";
$HELP .= "exit/quit            => exit console session\n";

my $LICENSE  = "SIPban  Copyright (C) 2019-2024 Fernando 'El Pop' Romo\n\n";
$LICENSE .= "This program comes with ABSOLUTELY NO WARRANTY;\n";
$LICENSE .= "for details https://www.gnu.org/licenses/gpl-3.0.en.html\n";
$LICENSE .= "This is free software, and you are welcome to redistribute\n";
$LICENSE .= "it under certain conditions.";

# open log file
open(LOG, ">> $Config{'log.file'}") or die;
LOG->autoflush(1);

print LOG Time_Stamp() . " SipBan Start\n";

#-----------------#
# Ipset functions #
#-----------------#

sub Ipset_Exists_Set {
    #/usr/sbin/ipset list -t sippban
    open(FH, "-|",  "$ips list -t $Config{'ipset.set_name'}") or die "Can't open pipe: $!";
    my @rv = <FH>;
    close(FH);
    if ( $rv[0] =~ /Name\: $Config{'ipset.set_name'}/g) {
        return 1;
    }
    else {
        return 0;
    }
}

sub Ipset_Create_Set {
    # /usr/sbin/ipset create sippban hash:ip hashsize 4096 timeout 604800
    my $rv = qx($ips create $Config{'ipset.set_name'} hash:ip hashsize 4096 timeout $Config{'ipset.timeout'});
    print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} created\n";
}

sub Ipset_Destroy_Set {
    # /usr/sbin/ipset destroy sippban
    my $rv = qx($ips destroy $Config{'ipset.set_name'});
    print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} destroyed\n";
}

sub Ipset_Save {
    # /usr/sbin/ipset save > /etc/sippban.dump
    my $rv = qx($ips save $Config{'ipset.set_name'} > $Config{'ipset.dump'});
    print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} saved\n";
}

sub Ipset_Restore_Set {
    if (-e $Config{'ipset.dump'}) {
        # /usr/sbin/ipset restore -! < /$SAVE_FILE/etc/sippban.dump
        my $rv = qx($ips restore -! < $Config{'ipset.dump'});
        print LOG Time_Stamp() . " IPSET => set $Config{'ipset.set_name'} restored\n";
    }
}

sub Ipset_Block {
    my ($ip, $msg) = @_;
    unless( exists($white_list{$ip}) ) {
        # /usr/sbin/ipset -q add sippban $ip > /dev/null
        my $rv = qx($ips -q add $Config{'ipset.set_name'} $ip);
        print LOG Time_Stamp() . " BLOCK => $ip ($msg)\n";
    }
}

sub Ipset_Unblock {
    my ($ip, $msg) = @_;
    unless( exists($white_list{$ip}) ) {
        # /usr/sbin/ipset -q add sippban $ip > /dev/null
        my $rv = qx($ips -q del $Config{'ipset.set_name'} $ip);
        print LOG Time_Stamp() . " BLOCK => $ip ($msg)\n";
    }
}

sub Ipset_Prune_Block {
    my $time = shift;
    foreach my $ip (sort keys %ban_ip) {
        if ($time >= $ban_ip{$ip}) {
            Ipset_Unblock($ip);
            delete $ban_ip{$ip};
        }
        else {
            if ($ban_ip{$ip} < $min_epoch) {
                $min_epoch = $ban_ip{$ip};
            }
        }
    }
    my $hash_size = keys %ban_ip;
    if ($hash_size <= 0) {
        $min_epoch = $max_epoch;
    }
}

#--------------------#
# Iptables functions #
#--------------------#

sub Iptables_Create_Chain {
    # /sbin/iptables -t filter -I INPUT -i eno1 -m set --match-set sipban src -j DROP
    my $rv = qx($ipt -t filter -I INPUT -i $Config{'iptables.interface'} -m set --match-set $Config{'ipset.set_name'} src -j $Config{'iptables.rule'});
    print print LOG Time_Stamp() . " CHAIN => $Config{'iptables.chain'} created\n";
}

sub Iptables_Erase_Chain {
    # /sbin/iptables -t filter -D INPUT -i eno1 -m set --match-set sipban src -j DROP
    my $rv = qx($ipt -t filter -D INPUT -i $Config{'iptables.interface'} -m set --match-set $Config{'ipset.set_name'} src -j $Config{'iptables.rule'});
    print LOG Time_Stamp() . " CHAIN => $Config{'iptables.chain'} erased\n";
}

#----------------------------------------------------------------------------------------------
# [Developer Note]: the process of each client request is declared in the %Client_Handler
#                   Hash and use references for speed operations in the event detection cycle.
#----------------------------------------------------------------------------------------------
my %Client_Handler = (
    "block" => sub {
        my $client = shift;
        my $control = shift;
        $out_buffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip) = $control->[1] =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if ($ip) {
                if (exists($ban_ip{$ip})) {
                    $out_buffer{$client} .= "$ip previously blocked\n";
                }
                else {
                    $ban_ip{$ip} = time() + $Config{'timer.ban'};
                    Ipset_Block($ip,'Manual block');
                    $out_buffer{$client} .= "$ip block\n";
                }
            }
            else {
                $out_buffer{$client} .= "$ip don't seems like a valid address\n";
            }
        }
        else {
            foreach my $ip (sort { $ban_ip{$a} <=> $ban_ip{$b} } keys %ban_ip) {
                $out_buffer{$client} .= Time_Stamp($ban_ip{$ip}) . " $ip\n";
            }
        }
    },
    "unblock" => sub {
        my $client = shift;
        my $control = shift;
        $out_buffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip) = $control->[1] =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if ($ip) {
                if (exists($ban_ip{$ip})) {
                    Ipset_Unblock($ip);
                    delete $ban_ip{$ip};
                    my $hash_size = keys %ban_ip;
                    if ($hash_size <= 0) {
                        $min_epoch = $max_epoch;
                    }
                    $out_buffer{$client} .= "$ip unblocked\n";
                }
                else {
                    $out_buffer{$client} .= "$ip is not previously blocked\n";
                }
            }
            else {
                $out_buffer{$client} .= "$ip don't seems like a valid address\n";
            }
        }
        else {
            $out_buffer{$client} .= "ip address missing\n";
        }
    },
    "save" => sub {
        my $client = shift;
        Ipset_Save();
        $out_buffer{$client} .= "ipset $Config{'ipset.set_name'} saved\n";
    },
    "restore" => sub {
        my $client = shift;
        Ipset_Restore($client);
        $out_buffer{$client} .= "ipset $Config{'ipset.set_name'} restore\n";
    },
    "help" => sub {
        my $client = shift;
        $out_buffer{$client} .= $HELP;
    },
    "uptime" => sub {
        my $client = shift;
        $out_buffer{$client} .= 'Uptime ' . Convert_To_Time(time() - $Start_Time). "\n";
    },
    "whois" => sub {
        my $client = shift;
        my $control = shift;
        $out_buffer{$client} .= '';
        if (exists($control->[1])) {
            my ($ip) = $control->[1] =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if ($ip) {
                $out_buffer{$client} .= "WHOIS information: $ip\n\n";
                my $response = ();
                my $status = eval { $response = whoisip_query($ip) } ;
                if ($response) {
                    foreach my $resp(sort keys(%{$response}) ) {
                        $out_buffer{$client} .= "$resp $response->{$resp} \n";
                    }
                }
                else {
                    $out_buffer{$client} .=  "No response from WHOIS servers\n";
                }
            }
            else {
                $out_buffer{$client} .= "$ip don't seems like a valid address\n";
            }
        }
        else {
            $out_buffer{$client} .= "ip address missing\n";
        }
    },
    "wl" => sub {
        my $client = shift;
        $out_buffer{$client} .= '';
        foreach my $ip (sort keys %white_list) {
            $out_buffer{$client} .= "$ip\n";
        }
    },
    "quit" => sub {
        my $client = shift;
        delete $in_buffer{$client};
        delete $out_buffer{$client};
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
            my ($prot, $remote_ip)  = $$packet_content_ref =~ /RemoteAddress\:\sIPV4\/(.*?)\/(.*?)\/.*?\n/isx;
            if ( ($service eq 'PJSIP') || ($service eq 'SIP') || ($service eq 'IAX') || ($service eq 'IAX2') || ($service eq 'AMI') ) {
                unless( exists($ban_ip{"$remote_ip"}) ) {
                    $ban_ip{$remote_ip} = time() + $Config{'timer.ban'};
                    Ipset_Block($remote_ip,'Invalid Account');
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
            my ($prot, $remote_ip)  = $$packet_content_ref =~ /RemoteAddress\:\sIPV4\/(.*?)\/(.*?)\/.*?\n/isx;
            if ( ($service eq 'PJSIP') || ($service eq 'SIP') || ($service eq 'IAX') || ($service eq 'IAX2') || ($service eq 'AMI') ) {
                unless( exists($ban_ip{"$remote_ip"}) ) {
                    $ban_ip{$remote_ip} = time() + $Config{'timer.ban'};
                    Ipset_Block($remote_ip,'Invalid Password');
                }
            }
        },
        #-----------------------------
        # Event: ChallengeSent
        # Privilege: security,all
        # EventTV: 2022-01-27T18:47:34.606-0300
        # Severity: Informational
        # Service: SIP
        # EventVersion: 1
        # AccountID: sip:127.0.0.1:9
        # SessionID: 0x7fe8480d4100
        # LocalAddress: IPV4/UDP/149.28.237.109/5060
        # RemoteAddress: IPV4/UDP/127.0.0.1/9
        # Challenge: 43ccaa48
        #-----------------------------
        "ChallengeSent" => sub {
            my $packet_content_ref = shift;
            my ($service)    = $$packet_content_ref =~ /Service\:\s(.*?)\n/isx;
            my ($account_id) = $$packet_content_ref =~ /AccountID\:\s(.*?)\n/isx;
            my ($prot, $remote_ip)  = $$packet_content_ref =~ /RemoteAddress\:\sIPV4\/(.*?)\/(.*?)\/.*?\n/isx;
            if ( ($service eq 'PJSIP') || ($service eq 'SIP') || ($service eq 'IAX') || ($service eq 'IAX2') || ($service eq 'AMI') ) {
                my $now = time();
                my ($count,$cached) = getCacheMatch($remote_ip);
                if($count != undef) {
                    $count++;
                    $cache{$remote_ip} = [ $count, $cached ];
                    if($count>$Config{'flood.count'}) {
                        unless( exists($ban_ip{"$remote_ip"}) ) {
                            $ban_ip{$remote_ip} = time() + $Config{'timer.ban'};
                            Ipset_Block($remote_ip,'Challenge Sent');
                        }
                    }
                } else {
                    $count=1;
                    $cache{$remote_ip} = [ $count, $now ];
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
    my $time = shift;
    $time = time() unless($time);
    my ($sec, $min, $hour, $day,$month,$year) = (localtime( $time ))[0,1,2,3,4,5];
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

sub getCacheMatch {
    my $check_value = shift;
    my $timeout = $Config{'flood.interval'};

    # Check cache for a match.
    my ($result, $time_cached);
    my $now = time();
    my $time_cached;
    my $cache_entry = $cache{$check_value};
    if ($cache_entry) {
        ($result, $time_cached) = @{$cache_entry};
        if ($now - $time_cached > $timeout) {
            delete $cache{$check_value};
            return undef;
        } else {
            return ($result, $time_cached);
       }
    }
}

sub Terminate {
    Iptables_Erase_Chain();
    Ipset_Save();
    Ipset_Destroy_Set();

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

#--------------------#
# Asterisk functions #
#--------------------#

sub Connect_To_Asterisk {
    my $host = shift;
    $asterisk_handler = new IO::Socket::INET->new( PeerAddr  => "$host",
                                                   PeerPort  => $Config{'ami.port'},
                                                   Proto     => "tcp",
                                                   ReuseAddr => 1,
                                                   Blocking  => 0,
                                                   Type      => SOCK_STREAM );
    if ($asterisk_handler) {
        $asterisk_handler->autoflush(1);
        $select->add($asterisk_handler);
        return 0;
    }
    else {
    	return 1;
    }
}

sub Send_To_Asterisk {
    my $command_ref = shift;
    if ($$command_ref ne '' && $manager_connect_flag == 0) {
        $out_buffer{$asterisk_handler} .= $$command_ref;
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

sub Manager_Login {
    my $command  = "Action: login\r\n";
    $command .= "Username: $Config{'ami.user'}\r\n";
    $command .= "Secret: $Config{'ami.pass'}\r\n";
    $command .= "Events: on\r\n\r\n";
    Send_To_Asterisk(\$command);
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
    # requests are in $in_buffer{$client}
    # send output to $out_buffer{$client}
    my $client = shift;
    my $request;

    foreach $request (@{$in_buffer{$client}}) {
       $request =~ s/\r|\n//g;
       if ($request) {
           my @control = split (/\s+/, Trim($request));
           if (exists($Client_Handler{$control[0]})) {
               $Client_Handler{$control[0]}->($client,\@control);
           }
           else {
               $out_buffer{$client} .= "Invalid command";
           }
       }
       if ($out_buffer{$client}) {
            $out_buffer{$client} .= "\nsipban>";
       } else {
            $out_buffer{$client} = 'sipban>';
       }
    }
    delete $in_buffer{$client};
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
    # send output to $out_buffer{$client}
    my $client = shift;
    my $request;
    my @packet = ();

    foreach $request (@{$in_buffer{$client}}) {
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
	       #    print "----- AMI -----\n$packet_content\n";
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
           $event_str = '';
       }
    }
    delete $in_buffer{$client};
}

sub Clean_Connection {
    my $client = shift;

    # Delete working buffers
    delete $in_buffer{$client};
    delete $out_buffer{$client};
    delete $sessions{$client};

    # Check if the connection to Asterisk Die and turn the reconnection Flag
    if ($client eq $asterisk_handler) {
    	$manager_connect_flag =1;
    }
    $select->remove($client);
    close($client);
}

#======================#
#      Main block      #
#======================#

# Load white list from file to hash %white_list
if (-e $Config{'iptables.white_list'}) {
    open WL, "< $Config{'iptables.white_list'}" || die "Can\'t open file\n";
    while(<WL>) { # Read records
        chomp;
        my ($ip) = $_ =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?)/;
        if ($ip) {
            $white_list{$_} = 1;
            print LOG Time_Stamp() . " WHITE LIST => $_\n";
        }
    }
    close (WL);
}

# Check if exists Ipset set
if ( Ipset_Exists_Set() ) {
    Ipset_Restore_Set();
}
else {
    if (-e $Config{'ipset.dump'}) {
        Ipset_Restore_Set();
    }
    else {
        Ipset_Create_Set();
    }
}


# Check if exists the chain name or else create one
my @Answer = qx($ipt -S $Config{'iptables.chain'});
if ($#Answer < 0) {
    Iptables_Create_Chain();
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
            $client->blocking(0);
            $select->add($client);
            $sessions{$client} = 1;
            $out_buffer{$client} = "\n$LICENSE\n\nuse 'help' for more commands\nsipban>";
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
            # test whether the data in the buffer or the data we
            # just read means there is a complete request waiting
            # to be fulfilled.  If there is, set $inbuffer{$client}
            # to the requests waiting to be fulfilled.
            while ($data =~ s/(.*\r\n)//) {
                push( @{$in_buffer{$client}}, $1 );
            }
        }
    }

    # Any complete requests to process?
    foreach $client (keys %in_buffer) {
        if ($client eq $asterisk_handler) {
            Handle_AMI($client);
        }
        else {
            Handle_Clients($client);
        }
    }

    # Timer operations
    my $current_time = time();
    if ($current_time >= $Ping_Time) {
        $Ping_Time += $Config{'ami.ping'};
        # print LOG Time_Stamp() . " Ping\n";
        Send_To_Asterisk(\"Action: Ping\r\n\r\n");
    }
    # Clean on block time lapse
    if ($current_time >= $min_epoch) {
        Ipset_Prune_Block($current_time);
    }

    # Buffers to flush?
    foreach $client ($select->can_write(1)) {
        # Skip this client if we have nothing to say
        next unless exists $out_buffer{$client};
        # Check if the socket exists before send
        ## if (defined(getpeername($client))) {
        unless($client eq "") {
            # use eval to isolate the send command in case of failure and continue the main process
            eval { $rv = $client->send($out_buffer{$client}, 0) };
            unless (defined $rv) {
                # Whine, but move on.
                warn "I was told I could write, but I can't.\n";
                next;
            }
            if ($rv == length $out_buffer{$client} ||
                $! == POSIX::EWOULDBLOCK) {
                substr($out_buffer{$client}, 0, $rv) = '';
                delete $out_buffer{$client} unless length $out_buffer{$client};
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
