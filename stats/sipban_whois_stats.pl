#!/usr/bin/perl
use strict;
use Net::Whois::IP qw(whoisip_query);

if ( $ARGV[0] ne '' ) {
    open P, "< $ARGV[0]" || die "Can\'t open file\n";

    my %attack_ip = ();

    while(<P>) { # Read records
        chomp;
        if ($_ =~ / BLOCK /) { 
            my ($ip) = $_ =~ / BLOCK => (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            if (not exists($attack_ip{$ip})) {
                $attack_ip{$ip}{count} = 1;
                my $response = ();
                my $status = eval { $response = whoisip_query($ip) };
                if (exists($response->{'Country'})) {
                    $attack_ip{$ip}{'Country'} = $response->{'Country'};
                }
                elsif (exists($response->{'country'})) {
                    $attack_ip{$ip}{'Country'} = $response->{'country'};
                }
                else {
                     $attack_ip{$ip}{'Country'} = '';
                }
                if (exists($response->{'City'})) {
                    $attack_ip{$ip}{'City'} = $response->{'City'};
                }
                elsif (exists($response->{'city'})) {
                    $attack_ip{$ip}{'City'} = $response->{'city'};
                }
                else {
                     $attack_ip{$ip}{'City'} = '';
                }
                $attack_ip{$ip}{'PostalCode'} = $response->{'PostalCode'};
                $attack_ip{$ip}{'StateProv'} = $response->{'StateProv'};
                $attack_ip{$ip}{'NetRange'} = $response->{'NetRange'};
                $attack_ip{$ip}{'Organization'} = $response->{'Organization'};
            }
            else {
                $attack_ip{$ip}{count}++;
            }
        }
    }

    foreach my $ip (sort {$attack_ip{$b}{count} <=> $attack_ip{$a}{count} or $a cmp $b} keys %attack_ip) {
            print "\"$ip\",$attack_ip{$ip}{count},\"$attack_ip{$ip}{'Country'}\",\"$attack_ip{$ip}{'City'}\",\"$attack_ip{$ip}{'StateProv'}\",\"$attack_ip{$ip}{'PostalCode'}\",\"$attack_ip{$ip}{'NetRange'}\",\"$attack_ip{$ip}{'Organization'}\"\n";
    }
    close (P);
}
else {
    print "Usage:\n    ./sipban_whois_stats.pl [sipban log file]\n";
}
