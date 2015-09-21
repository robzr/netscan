#!/usr/bin/perl
#
# Multithreaded network scanning module -- Rob Zwissler
#

use strict;
use v5.10.1;
use warnings;
use threads;
use threads::shared;  # threads->list() threads::all == undef, threads::running == true, threads::joinable == false
use NetAddr::IP;      # to parse CIDR format

package netscan;

our @ips;
my %cmds;
my %cmdArgs = ('nmap' => '--host-timeout 2 -sn',
  'ssh' =>  '-noBatchMode=yes -oPasswordAuthentication=no -oStrictHostKeyChecking=no -oLogLevel=fatal -oConnectTimeout=2');

my %isLive :shared;
my $maxThreads = 100;

# Given argument of an ip, returns boolean isLive
#
sub isLive { return $isLive{shift @_} }

# usage: netscan->callSub( (optional) maxThreads, \&sub, (optional) argument, argument...);
#        maxThreads -1 = default, 0 = unlimited (system throttled)...
#
sub callSub {
  # args: (optional) maxThreads, subroutine, args...
  #       last 2 args will be (ip, boolean status)
  my $subMaxThreads = $maxThreads;
  shift;
  my $sub = shift;
  if(ref($sub) eq '') {
    $subMaxThreads = ($sub == -1)?$maxThreads:$sub;
    $sub = shift;
  }
  my @args = @_;

  runThreaded($subMaxThreads, sub { $sub->(@args, $_[0], isLive($_[0])) }, 0, @ips);
}

# args: (optional) maxThreads, command, output, (optional) short_result_hash_ref, (optional) IP list
#       maxThreads - unused or -1 uses default; 0 is automatic (throttled by OS), any other number is max # of threads
#       command is the command, of course
#       output can be a filename, or a hash reference which will be keyed on host IP.  Hashes must be share()'d due to multithreading
#       short_result_hash_ref - hash reference (must be shared())  
#
# example: netscan->runProg(50, '/bin/ls /etc/ | wc -l', '/tmp/files_in_etc.%s');
#          netscan->runProg('hostname', share(%hostnames), my %status :shared);
#
sub runProg {
  shift if($_[0] eq 'netscan');
  my $subMaxThreads = $maxThreads;
  my $cmd = shift;
  if($cmd =~ /^\d+$/) {
    $subMaxThreads = ($cmd == -1)?$maxThreads:$cmd;
    $cmd = shift;
  }
  my $longResults = ($#_ > -1)?shift:{};
  my $shortResults = ($#_ > -1)?shift:{};
  my @subIps = ($#_ > -1)?@_:@ips;

  main::share($longResults) if(!main::is_shared($longResults));
  main::share($shortResults) if(!main::is_shared($shortResults));

  runThreaded($subMaxThreads, \&runProgSingle, 3, $cmd, $longResults, $shortResults, @subIps);
}

sub runProgSingle {
  # used internally. args: command, long_result_ref, short_result_ref, ip
  #
  # example: runProg('hostname', \$shortResult, \@longResult, 10.14.50.11);
  # -or to write to a file-
  #   runProg('hostname', "/tmp/output.$ip", \$shortResult, $ip);
  #
  shift if($_[0] eq 'netscan');
  my $cmd = shift;

  my ($longResult, $shortResult, $ip, $ip2) = @_;

  $isLive{$ip} = checkHostLive($ip) if(!defined $isLive{$ip});
  if(!$isLive{$ip}) {
    (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = 'NOT_LIVE';
    return -1;
  }

  # add buffer of short result !!!

  do {
    my $fmtCmd = $cmd;
    $fmtCmd =~ s/'/\\'/g;
    open(SSH, sprintf('%s %s %s \'%s\' 2>&1 |', $cmds{'ssh'}, $cmdArgs{'ssh'}, $ip, $fmtCmd));
    usleep(500) if($? == 32768);
  } while($? == 32768);
  my @output = <SSH>;
  close(SSH);

  if($? == 65280 && defined $output[0]) {
    given($output[0]) {
      # with LogLevel=fatal these first two will be caught by the catch-all unfortunately
      when(/Operation timed out/) { (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = 'CONN_TIMEOUT' }
      when(/Connection refused/)  { (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = 'CONN_REFUSED' }
      when(/Permission denied/)   { (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = 'PERM_DENIED' }
      default                     { (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = 'CONN_BAD' }
  } } else { (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = 'SUCCESSFUL'.(($?)?"_$?":''); }

  given(ref($longResult)) {
    when('SCALAR') { $$longResult = join('', @output) }
    when('ARRAY')  { @{$longResult} = @output }
    when('HASH')   { $longResult->{$ip} = join('', @output) }
    when('')       { 
        if($? != 65280) {
          if((ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} =~ /^SUCCESSFUL/ && open(OUT, '>', sprintf($longResult, $ip))) {
             print OUT @output;
             close(OUT);
          } else { (ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} = /BAD_OUTPUT_FILE/ }
  } } }
  return ((ref($shortResult) eq 'SCALAR')?$$shortResult:$shortResult->{$ip} =~ /^SUCCESSFUL_/)?1:-1;
}


sub runThreaded {
  # args: (optional) maxThreads, sub reference, argc, (optional) argv..., list_to_iterate 
  #  maxThreads = -1 = default, 0 = unlimited...
  #  reference to the subroutine to run
  #  if there are common args, use argc & argv to pass them, else use argc = 0
  #  finally, list of argument to launch one thread for each member
  my $subMaxThreads = $maxThreads;
  my $sub = shift;

  if(ref($sub) eq '') {
    $subMaxThreads = ($sub == -1)?$maxThreads:$sub;
    $sub = shift;
  }
  $subMaxThreads = 99999 if($subMaxThreads == 0);  # let the system throttle it

  my $staticArgCount = shift;
  my @staticArgs = ($staticArgCount)?@_[0..($staticArgCount - 1)]:undef;
  my @args = @_[$staticArgCount..$#_];

  foreach my $arg (@args) { 
    do { &joinThreads || threads->yield();
    } while(scalar(threads->list()) >= $subMaxThreads || ! defined threads->create({'context' => 'scalar'}, $sub, ($#staticArgs > 0)?(@staticArgs, $arg):$arg));
  }
  do { threads->yield() } while(scalar(threads->list(1)) > 0);
  &joinThreads;
}

sub joinThreads {
  my $joined = 0;
  if(scalar(threads->list(0)) > 0) {
    for my $thread (threads->list(0)) {
      $thread->join();
      $joined++;
  } }
  return $joined;
}

sub checkHostLive {
  my $ip = shift;
  my $ret;

  do {
    system($cmds{'ping'}." -c 1 -t 2 $ip 2>&1 >/dev/null");
    $ret = $?;
    usleep(500) if($ret == 32768);
  } while($ret == 32768);

  if($ret != 0) {
    do {
      system($cmds{'nmap'}.' '.$cmdArgs{'nmap'}." $ip 2>&1 | fgrep -q 'Host is up' 2>&1 >/dev/null");
      $ret = $?;
      usleep(500) if($ret == 32768);
    } while($ret == 32768);
  }
  return ($ret == 0)?1:0;
}

sub nsDie {
  print "netscan.pm error: $_[0]\n"; 
  exit -1; 
}

sub findCmd {
  foreach my $cmd (@_) { return $cmd if(-x $cmd); } 
  return undef;
}

sub sortbyip { 
  shift if($_[0] eq 'netscan');
  return sort byip @_;
}
sub byip { 
  map { (split /\./, $a)[$_] == (split /\./, $b)[$_] || return (split /\./, $a)[$_] <=> (split /\./, $b)[$_] } (0..3); 
}


our (@ISA, @EXPORT_OK);
sub BEGIN { 
  require Exporter;
  @ISA = qw(Exporter);
  @EXPORT_OK = qw(runProg);

  $cmds{'ping'} = findCmd(qw(/sbin/ping /bin/ping))              || nsDie "Could not locate command ping";
  $cmds{'nmap'} = findCmd(qw(/usr/local/bin/nmap /usr/bin/nmap)) || nsDie "Could not locate command nmap";
  $cmds{'ssh'} = findCmd(qw(/usr/bin/ssh))                       || nsDie "Could not locate command ssh";

  return 1; 
}

sub populateIsLive { $isLive{$_[0]} = checkHostLive($_[0]) }

sub import {
  shift;
  while(my $subnet = shift) {
    my $netaddr = NetAddr::IP->new($subnet);
    push(@ips, @{$netaddr->hostenumref});
  }
  @ips = sort byip map { s/\/32//g; $_ } @ips;
  runThreaded(\&populateIsLive, 0, @ips);

  netscan->export_to_level(1, qw(netscan), qw(&runProg));
  
  return 1;
}

sub END { return 1; }

1;
