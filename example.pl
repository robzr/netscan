#!/usr/bin/perl 

use netscan(qw(192.168.1.0/24));

sub printIt {
  my ($test, $ip, $status) = @_;
  printf "Starting IP %s (%s)...\n", $ip, $test;
  sleep(3);
  printf "Finishing IP %s: %d\n", $ip, $status;
}
#netscan->callSub(0, \&printIt, "hi mom");

my %hostnames :shared;
my %status :shared;

#netscan::runProg('hostname', \%hostnames, \%status);

runProg('hostname', \%hostnames, \%status);
#runProg('hostname', "/tmp/xxx.", \%status);

printf "Finished, got %d results.\n", scalar(keys %status);

foreach my $x ( netscan->sortbyip(keys %status)) {
  chomp($hostnames{$x});
#  printf "IP %s - %s (%s)\n", $x, $status{$x}, $hostnames{$x} if($status{$x} eq 'SUCCESSFUL');
  printf "IP %s - %s (%s)\n", $x, $status{$x}, $hostnames{$x};
}

exit;

