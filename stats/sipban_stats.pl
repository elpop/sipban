#!/usr/bin/perl
use strict;

if ( $ARGV[0] ne '' ) {
    open P, "< $ARGV[0]" || die "Can\'t open file\n";

    my %attack_ip = ();

    while(<P>) { # Read records
        chomp;
        if ($_ =~ / BLOCK /) { 
            my ($ip) = $_ =~ / BLOCK => (\d+\.\d+\.\d+\.\d+)/;
            if (not exists($attack_ip{$ip})) {
                $attack_ip{$ip} = 1;
            }
            else {
                $attack_ip{$ip}++;
            }
        }
    }

    foreach my $ip (sort {$attack_ip{$b} <=> $attack_ip{$a} or $a cmp $b} keys %attack_ip) {
        print "$ip => $attack_ip{$ip}\n";
    }
    close (P);
}
else {
    print "Usage:\n    ./sipban_stats.pl [sipban log file]\n";
}
