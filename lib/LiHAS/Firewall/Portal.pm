package LiHAS::Firewall::Portal;
use warnings;
use strict;
use POE;
use XML::Application::Config;
use POE::Component::Server::TCP;
use Log::Log4perl qw(:easy);

sub TIMER_DELAY { 10 };
sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions


sub http_redirector {
  my ($kernel,$heap,$response) = @_[KERNEL, HEAP, ARG0];
  POE::Component::Server::TCP->new(
    Port => 81,
    ClientConnected => sub {
      $_[HEAP]{client}->put(
"HTTP/1.1 302 Found
Location: http://portalserver.lan:82/
Expires: Sat, 01 Jan 2000 00:00:00 GMT
Connection: close
");
      $_[KERNEL]->yield("shutdown");
    },
    ClientInput => sub {
      my $client_input = $_[ARG0];
    },
  );
}

sub portal_ipset_init {
  my ($kernel,$heap,$response) = @_[KERNEL, HEAP, ARG0];
  DEBUG "portal_ipset_init";
  if ($heap->{feature_portal}!=1) { return 0;}
  my ($ipsetname,$ip,$mac,$start_date,$end_date);
  my $sql = "UPDATE portal_clients SET active=0";
  my $sth = $heap->{dbh}->prepare($sql);
  my $sth1;
  my $time=0;
  my $timestamp=time();
  open(IPSET, '|ipset -exist restore');
  # clean ipset
  $sql = "SELECT DISTINCT portalname FROM portal_clients";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute();
  $sth->bind_columns(\$ipsetname);
  while ( $sth->fetch ) {
    print IPSET 'flush pswap$ipsetname\n';
  }
# fill ipset
  $sql = "SELECT DISTINCT portalname,ip,mac,start_date,end_date FROM portal_clients WHERE start_date<? AND end_date>? AND active=0";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute($timestamp, $timestamp);
  $sql = "UPDATE portal_clients SET active=1 WHERE portalname=? AND ip=? AND mac=? AND start_date=? AND end_date=?";
  $sth1 = $heap->{dbh}->prepare($sql);
  $sth->bind_columns(\$ipsetname, \$ip, \$mac, \$start_date, \$end_date);
  while ( $sth->fetch ) {
    print IPSET "add pswap$ipsetname $ip,$mac\n";
    $sth1->execute($ipsetname, $ip, $mac, $start_date, $end_date);
  }
  # activate ipset
  $sql = "SELECT DISTINCT portalname FROM portal_clients";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute();
  $sth->bind_columns(\$ipsetname);
  while ( $sth->fetch ) {
    print IPSET "swap $ipsetname pswap$ipsetname\n";
  }
  close IPSET;
  # save expired entries to history and delete from active clients
  $sql = "SELECT portalname,ip,mac,start_date,end_date FROM portal_clients WHERE active=0";
  $sth = $heap->{dbh}->prepare($sql);
  $sql = "INSERT INTO portal_clienthistory (portalname,ip,mac,start_date,end_date) VALUES (?,?,?,?,?)";
  $sth1 = $heap->{dbh}->prepare($sql);
  $sth->execute();
  $sth->bind_columns(\$ipsetname, \$ip, \$mac, \$start_date, \$end_date);
  while ( $sth->fetch ) {
    $sth1->execute($ipsetname,$ip,$mac,$start_date,$end_date);
  }
  $sql = "DELETE FROM portal_clients WHERE active=0";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute();
  my $nextcall;
  $sql = "SELECT min(end_date) AS time FROM portal_clients";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute();
  $sth->bind_columns(\$time);
  $sth->fetch;
  if ( ! defined ($time) ) { $time=$timestamp+60; }
  $nextcall=$time-$timestamp;
  if ($nextcall<1) {
    $kernel->delay('portal_ipset_init', 1);
  } else {
    $kernel->delay('portal_ipset_init', $nextcall);
  }
}

1;
