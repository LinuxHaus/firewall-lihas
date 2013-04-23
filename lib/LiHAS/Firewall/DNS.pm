package LiHAS::Firewall::DNS;
use warnings;
use strict;
use POE;
use XML::Application::Config;

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
  if ( not defined $response->{response} ) {
    return 0;
  }
  @answers = $response->{response}->answer();
  my $sql;
  my $sth;
  my $sth1;
  my ($count, $hostname, $time_first, $time_valid_till, $ip);
  if ( $#answers > 0 ) {
    die "DNS is not supported for hosts resolving to more than 1 address: ".$response->{host};
  }
  foreach my $answer (@answers) {
    print(
      time(), " $response->{host} ",
      $answer->ttl(), " ",
      $answer->type(), " ",
      $answer->rdatastr(), "\n"
    );
    $sql = "SELECT count(*), hostname, time_first, time_valid_till, ip FROM hostnames_current WHERE hostname=?";
    $sth = $heap->{dbh}->prepare($sql);
    $sth->execute($response->{host});
    $sth->bind_columns(\$count, \$hostname, \$time_first, \$time_valid_till, \$ip);
    while ( $sth->fetch ) {
      if ($count == 0) {
        $sql = "INSERT INTO hostnames_current (hostname, time_first, time_valid_till, ip) VALUES (?, ?, ?, ?)";
	$sth1 = $heap->{dbh}->prepare($sql);
	$sth1->execute($response->{host}, time(), time()+$answer->ttl(), $answer->rdatastr());
	$sql = "UPDATE vars_num SET value=? WHERE name=?";
	$sth1 = $heap->{dbh}->prepare("$sql");
        $sth1->execute(1,'fw_reload_dns');
	$kernel->delay('firewall_reload_dns',10);
      } elsif ($count == 1) {
        if ($answer->rdatastr() !~ /^$ip$/) {
          $sql = "INSERT INTO dnshistory (hostname, time_first, time_valid_till, ip, active) VALUES (?, ?, ?, ?, ?)";
	  $sth1 = $heap->{dbh}->prepare($sql);
	  $sth1->execute($response->{host}, time(), time()+$answer->ttl(), $answer->rdatastr(), 0);
          $sql = "UPDATE hostnames_current SET time_valid_till=?, ip=? WHERE hostname=?";
	  $sth1 = $heap->{dbh}->prepare($sql);
	  $sth1->execute(time()+$answer->ttl(), $answer->rdatastr(), $response->{host});
	  $sql = "UPDATE vars_num SET value=? WHERE name=?";
	  $sth1 = $heap->{dbh}->prepare("$sql");
          $sth1->execute(1,'fw_reload_dns');
	  $kernel->delay('firewall_reload_dns',10);
        } else {
          $sql = "UPDATE hostnames_current SET time_valid_till=? WHERE hostname=? AND ip=?";
	  $sth1 = $heap->{dbh}->prepare($sql);
	  $sth1->execute(time()+$answer->ttl(), $response->{host}, $answer->rdatastr());
        }
      } else {
        die "DNS is not supported for hosts resolving to more than 1 address: ".$response->{host};
      }
    }
  }
}

1;
