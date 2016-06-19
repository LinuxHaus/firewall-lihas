package LiHAS::Firewall::Portal;
use warnings;
use strict;
use POE;
use XML::Application::Config;
use Log::Log4perl qw(:easy);

sub TIMER_DELAY { 10 };
sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions


=head3 Function portal_init
Gets called on startup to prefill database with persistent clients
=cut

sub portal_init {
  my ($kernel,$heap) = @_[KERNEL, HEAP];
	my $sql;
	my $sth;
	my ($ip, $mac, $comment, $count);
	my $portalname=$heap->{portalname};
	my $configpath=$heap->{configpath};
  DEBUG "portal_init";
	$sql = "SELECT count(*) AS count FROM portal_clients WHERE portalname=? AND ip=? AND mac=? AND start_date=0 AND end_date=2147483647";
	my $sthcheck = $heap->{dbh}->prepare($sql);
	# $sthcheck->execute($portalname,$ip,$mac);
	$sql = "INSERT INTO portal_clients (portalname,ip,mac,start_date,end_date,active,userid) VALUES (?,?,?,0,2147483647,0,0)";
	my $sthupdate = $heap->{dbh}->prepare($sql);
	# $sthupdate->execute($portalname,$ip,$mac);
  if (open(my $fh, "<", "$configpath/feature/portal/$portalname/clients-static")) {
    foreach (<$fh>) {
			/^#/ && next;
	  	($mac,$ip,$comment) = split /[\s\r\n]+/;
	  	$comment =~ s/"//g; # No " allowed in ipset comments
	  	$mac =~ y/[A-Z]/[a-z]/;
	  	if ($ip !~ m/(2[0-5][0-9]|1[0-9]{0,2}|[1-9][0-9]{0,1})/) { ERROR "$ip is no IP"; }
	  	elsif ($mac !~ m/([a-f0-9]{1,2}:){5}[a-f0-9]{1,2}/ ) { ERROR "$mac is no MAC"; }
	  	else {
	  		$sthcheck->execute($portalname,$ip,$mac);
	  		$sthcheck->bind_columns(\$count);
	  		$sthcheck->fetch;
	  		if ($count==0) {
	  			$sthupdate->execute($portalname,$ip,$mac);
	  		}
	  	}
    }
	  close($fh);
	}
}

=head3 Function portal_ipset_init
gets called periodically to update the ipset
=cut

sub portal_ipset_init {
  my ($kernel,$heap,$response) = @_[KERNEL, HEAP, ARG0];
  DEBUG "portal_ipset_init";
  if ($heap->{feature_portal}!=1) { return 0;}
  my ($ipsetname,$ip,$mac,$start_date,$end_date,$id,$name,$pass);
  my $sql = "UPDATE portal_clients SET active=0";
  my $sth = $heap->{dbh}->prepare($sql);
  $sth->execute();
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
    print IPSET "flush pswap$ipsetname\n";
  }
# fill ipset
  $sql = "SELECT DISTINCT portalname,ip,mac,start_date,end_date FROM portal_clients WHERE start_date<=? AND end_date>=? AND active=0";
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
  # save expired voucher entries to history and delete
# CREATE TABLE IF NOT EXISTS portal_users ( id INTEGER PRIMARY KEY, name TEXT NOT NULL, pass TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL, max_duration TEXT, max_clients TEXT, start_use TEXT);
  $sql = "SELECT id,name,pass,start_date,end_date FROM portal_users WHERE end_date<?";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute($timestamp);
  $sql = "INSERT INTO portal_usershistory (name,pass,start_date,end_date) VALUES (?,?,?,?)";
  $sth1 = $heap->{dbh}->prepare($sql);
  $sth->bind_columns(\$id, \$name, \$pass, \$start_date, \$end_date);
  while ( $sth->fetch ) {
		DEBUG "INSERT INTO portal_usershistory (name,pass,start_date,end_date) VALUES ($name,$pass,$start_date,$end_date)";
    $sth1->execute($name,$pass,$start_date,$end_date);
  }
	$sql = "DELETE FROM portal_users WHERE end_date<=?";
  $sth = $heap->{dbh}->prepare($sql);
	DEBUG "DELETE FROM portal_users WHERE end_date<=$timestamp";
  $sth->execute($timestamp);
  # save expired client entries to history and delete from active clients
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
# vim: ts=2 sw=2 sts=2 sr noet
1;
