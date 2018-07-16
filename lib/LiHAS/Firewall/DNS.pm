package LiHAS::Firewall::DNS;
use warnings;
use strict;
use POE;
use XML::Application::Config;
use Log::Log4perl qw(:easy);

sub TIMER_DELAY { 10 };
sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions

my $named = POE::Component::Client::DNS->spawn(
  Alias => "named"
);

#------------------------------------------------------------------------------
# This session uses the ping component to resolve things.
sub dns_query {
  my ($kernel, $heap, $type, $name) = @_[KERNEL, HEAP, ARG0, ARG1];
  my $response = $named->resolve(
    event   => "dns_response",
    host    => $name,
    type    => $type,
    context => { },
    timeout => 20,
  );
  if ($response) {
    $kernel->yield(dns_response => $response);
  }
}

sub dns_update {
  my ($kernel,$heap,$response) = @_[KERNEL, HEAP, ARG0];
  my $hostname;
  my $sql = "SELECT DISTINCT hostname FROM hostnames_current WHERE time_valid_till<?";
  my $sth = $heap->{dbh}->prepare($sql);
  $sth->execute(time());
  $sth->bind_columns(\$hostname);
  while ( $sth->fetch ) {
    $kernel->yield("dns_query", 'A', $hostname);
  }
  $kernel->delay('dns_update', $heap->{refresh_dns_minimum});
}

sub dns_response {
  my ($kernel,$heap,$response) = @_[KERNEL, HEAP, ARG0];
  my @answers;
  my %dnsips;
  my $ttl;
  if ( not defined $response->{response} ) {
    return 0;
  }
  @answers = $response->{response}->answer();
  my $sql;
  my $sth;
  my $sth1;
  my ($count, $hostname, $time_first, $time_valid_till, $ip);
# Plan to support multiple answers:
# select all current answers from database for a host into a hash dnsips{$ip}=0
# do the dnslookup, write Ips into dnsips{$ip}=ttl
# iterate on keys %dnsips, if $dnsips{$ip}=0 -> copy db-entry to history and delete it
# if $dnsips{$ip}>0 update/insert entry
  $sql = "SELECT hostname, time_first, time_valid_till, ip FROM hostnames_current WHERE hostname=?";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute($response->{host});
  $sth->bind_columns(\$hostname, \$time_first, \$time_valid_till, \$ip);
  while ( $sth->fetch ) {
    $dnsips{$ip}{ttl}=0;
    $dnsips{$ip}{time_first}=$time_first;
    $dnsips{$ip}{time_valid_till}=$time_valid_till;
  }
  foreach my $answer (@answers) {
    print(
      time(), " $response->{host} ",
      $answer->ttl(), " ",
      $answer->type(), " ",
      $answer->rdatastr(), "\n"
    );
    $dnsips{$answer->rdatastr()}{ttl}=$answer->ttl;
  }
  foreach my $ip (keys %dnsips) {
    if ($dnsips{$ip}{ttl} == 0) {
      $sql = "INSERT INTO dnshistory (hostname, time_first, time_valid_till, ip, active) VALUES (?, ?, ?, ?, ?)";
      $sth1 = $heap->{dbh}->prepare($sql);
      $sth1->execute($response->{host}, $dnsips{$ip}{time_first}, $dnsips{$ip}{time_valid_till}, $ip, 0);
      $sql = "UPDATE vars_num SET value=? WHERE name=?";
      $sth1 = $heap->{dbh}->prepare("$sql");
      $sth1->execute(1,'fw_reload_dns');
      $kernel->delay('firewall_reload_dns',10);
    } else {
      if ( ! defined($dnsips{$ip}{time_first}) ) {
	# new entry
        $sql = "INSERT INTO hostnames_current (hostname, time_first, time_valid_till, ip) VALUES (?, ?, ?, ?)";
	$sth1 = $heap->{dbh}->prepare($sql);
	$sth1->execute($response->{host}, time(), time()+$dnsips{$ip}{ttl}, $ip);
        $sql = "UPDATE vars_num SET value=? WHERE name=?";
        $sth1 = $heap->{dbh}->prepare("$sql");
        $sth1->execute(1,'fw_reload_dns');
        $kernel->delay('firewall_reload_dns',10);
      } else {
        $sql = "UPDATE hostnames_current SET time_valid_till=? WHERE hostname=? AND ip=?";
        $sth1 = $heap->{dbh}->prepare($sql);
        $sth1->execute(time()+$dnsips{$ip}{ttl}, $response->{host}, $answer->rdatastr());
      }
    }
  }
}

1;
