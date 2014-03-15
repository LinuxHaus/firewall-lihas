#!/usr/bin/perl -w
# Copyright (C) 2011-2013 Adrian Reyer support@lihas.de
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

=head1 NAME

portal-cgi.pl

Take credentials and redirect to next page

=cut

use warnings;
use strict;

use XML::Application::Config;
use DBI;
use CGI;
use URI::Escape qw(uri_escape);
use Digest::SHA qw(sha1_base64);

my $cfg = new XML::Application::Config("LiHAS-Firewall","/etc/firewall.lihas.d/config.xml");
my $dbh = DBI->connect($cfg->find('database/dbd/@connectorstring'));
print STDERR "DB Connect: ".$cfg->find('database/dbd/@connectorstring');
my ($sth, $sql, $sth1);
my ($name, $pass, $start_date, $end_date, $max_duration, $max_clients, $start_use, $userrowid);
my ($time, $enddate);
my ($ip, $hw, $mac, $dummy);

=head1 Functions
=cut

my $cgi = CGI->new;
my %auth;
my $message='';
my @param = $cgi->param;
foreach (@param) {
	print STDERR "$_: ".$cgi->param($_)."\n";
}
my $error=0;
if ($cgi->param('accept')=~/Anmelden/ ) {
	if (! defined $cgi->param('accept_tos') || $cgi->param('accept_tos') !~ /^ja$/) {
	    $message = "TOS";
	    $error = 1;
	} elsif (! defined $cgi->param('auth_user') || $cgi->param('auth_user') !~ /^[\+0-9a-zA-Z_-]+$/) {
	    $message = "Invalid User";
	    $error = 1;
	} elsif (! defined $cgi->param('auth_pass') || $cgi->param('auth_pass') !~ /^[\+0-9a-zA-Z_-]+$/) {
	    $message = "Invalid Password";
	    $error = 1;
	} else {
		$sql = "SELECT name,pass,start_date,end_date,max_duration,max_clients,start_use,id FROM portal_users WHERE name=? AND pass=?";
	  $sth = $dbh->prepare($sql);
	  $sth->execute($cgi->param('auth_user'), $cgi->param('auth_pass'));
	  $sth->bind_columns(\$name, \$pass, \$start_date, \$end_date, \$max_duration, \$max_clients, \$start_use, \$userrowid);
	  while ( $sth->fetch ) {
			$time = time();
			if ( $max_clients>0 ) {
				if ( $start_date < $time ) {
					if ( $end_date > $time ) {
						# client valid, activate
						if ($start_date+$time < $end_date) {
							$enddate = $start_date+$time;
						} else {
							$enddate = $end_date;
						}
						open(my $arp, "/usr/sbin/arp -n ".$cgi->remote_addr." |");
						while (<$arp>) {
							($ip, $hw, $mac, $dummy) = split;
							if ( $hw =~ m/ether/ ) {
								last;
							}
						}
						print STDERR "mac: $mac\n";
						close($arp);
						$sql = "SELECT userid FROM portal_clients WHERE mac=?";
						$sth1 = $dbh->prepare($sql);
						$sth1->execute($mac);
						if ( $sth1->fetch ) {
							print STDERR "Update $enddate\n";
						  $sql = "UPDATE portal_clients SET end_date=? WHERE mac=?";
							$sth1 = $dbh->prepare($sql);
							$sth1->execute($enddate,$mac);
						} else {
							$sql = "INSERT INTO portal_clients (portalname, ip, mac, start_date, end_date, active, userid) VALUES (?,?,?,?,?,0,?);";
							$sth1 = $dbh->prepare($sql);
							$sth1->execute($cfg->find('feature/portal/name'),$cgi->remote_addr,$mac,$time,$enddate,$userrowid);
							$sql = "UPDATE portal_users SET max_clients=max_clients-1 WHERE id=?";
							$sth1 = $dbh->prepare($sql);
							$sth1->execute($userrowid);
						}
						#my $firewallclient = new LWP::UserAgent;
						#$firewallclient->agent("lihas-fw/1.0");
						#my $request = new HTTP::Request('GET','<application name="LiHAS-Firewall"><manage><feature><portal><cmd name="reload">reload</cmd></portal></feature></manage></application>');
						#my $response = $ua->request($request);
						open(FW, "| nc localhost 83 >/dev/null 2>&1") || die "nc failed\n";
						print FW '<application name="LiHAS-Firewall"><manage><feature><portal><cmd name="reload">reload</cmd></portal></feature></manage></application>\n';
						close(FW);
						print $cgi->redirect(
							-uri=>$cfg->find('feature/portal/page_ok').'?message='.uri_escape("$message"),
							-expires=>'Sat, 01 Jan 2000 00:00:00 GMT',
						);
					} else {
						$message = "Ticket already expired.";
# Move user to history
						$sql = "INSERT INTO portal_usershistory (name, pass, start_date, end_date, max_duration, max_clients, start_use) VALUES (?,?,?,?,?,?,?)";
						$sth1 = $dbh->prepare($sql);
						$sth1->execute($name, $pass, $start_date, $end_date, $max_duration, $max_clients, $start_use);
						$sql = "DELETE FROM portal_users WHERE ROWID=?";
						$sth1 = $dbh->prepare($sql);
						$sth1->execute($userrowid);
						$error = 1;
					}
				} else {
					$message = "Ticket not valid, yet.";
					$error = 1;
				}
			} else {
	      $message = "Too many concurrent clients.";
				$error = 1;
			}
	  }
	}
} elsif ( $cgi->param('accept')=~/Registrieren/ ) {
	my $hash;
# SMS Identification
	if (! defined $cgi->param('auth_user') || $cgi->param('auth_user') !~ /^[\+0-9]+$/) {
	  $message = "Invalid User";
	  $error = 1;
	} else {
	  $hash=sha1_base64(rand()*1000000000000000);
	  $hash =~ s/^(.{8}).*/$1/;

	  $sql = "INSERT INTO portal_users (name, pass, start_date, end_date, max_duration, max_clients) VALUES (?,?,?,?,?,?)";
	  $sth1 = $dbh->prepare($sql);
	  $sth1->execute($cgi->param('auth_user'),$hash,time(),time()+$cfg->find('feature/portal/password/sms/expire'),$cfg->find('feature/portal/session/expire'),$cfg->find('feature/portal/password/sms/clients_max'));
	  print $cgi->header();
		print STDERR "wget -O- https://gw.mobilant.net/?key=".$cfg->find('feature/portal/password/sms/mobilant/key')."&to=".$cgi->param('auth_user')."&message=".uri_escape($cfg->find('feature/portal/password/sms/mobilant/from')." WLAN Key: ".$hash)."&route=lowcostplus&from=".uri_escape($cfg->find('feature/portal/password/sms/mobilant/from'))." |";
		open(SMS, "wget -O- 'https://gw.mobilant.net/?key=".$cfg->find('feature/portal/password/sms/mobilant/key')."&to=".$cgi->param('auth_user')."&message=".uri_escape($cfg->find('feature/portal/password/sms/mobilant/from')." WLAN Key: ".$hash)."&route=lowcostplus&from=".uri_escape($cfg->find('feature/portal/password/sms/mobilant/from'))."' |");
		while (<SMS>) {
			print STDERR "SMS: $_";
		}
		close(SMS);
	}
}

if ( $error == 1 ) {
	print $cgi->header();
	print "<h1>$error</h1>"
} else {
	print $cgi->header();
}

exit 0;
# vim: ts=2 sw=2 sts=2 sr noet
