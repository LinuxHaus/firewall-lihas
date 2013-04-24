#!/usr/bin/perl
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

# Requirements: libxml-application-config-perl liblog-log4perl liblog-dispatch-perl

BEGIN {
  use Net::Server::Daemonize qw(daemonize check_pid_file unlink_pid_file);    # or any other daemonization module
  daemonize(root => root => '/var/state/firewall-lihasd.pid');
}

use Log::Log4perl qw(:easy);
Log::Log4perl::init('/etc/firewall.lihas.d/log4perl.conf');
if (! Log::Log4perl::initialized()) { WARN "uninit"; } else { WARN "init"; }

=head1 NAME

firewall-lihasd
Daemon supporting firewall-lihas.de by resolving dns-names

=cut

use warnings;
use strict;

$SIG{__WARN__} = sub {
  local $Log::Log4perl::caller_depth =
        $Log::Log4perl::caller_depth + 1;
  WARN @_;
};

use XML::Application::Config;
use POE qw(Component::Client::Ping Component::Client::DNS );
# use Test::More skip_all => "Derzeit keine Tests";
use lib "/etc/firewall.lihas.d/lib";
use LiHAS::Firewall::Ping;
use LiHAS::Firewall::DNS;
use DBI;

my $cfg = new XML::Application::Config("LiHAS-Firewall","/etc/firewall.lihas.d/config.xml");

=head1 Functions

=head2 firewall_reload_dns

Reloads the iptables dns-* chains with current IPs from database
=cut
sub firewall_reload_dns {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
  if (! Log::Log4perl::initialized()) { DEBUG "firewall_reload_dns: uninit"; } else { DEBUG "firewall_reload_dns: init"; }
  my @replacedns;
  my ($hostname, $ip, $table);
  my ($dh, $fh, $line, $iptupdate, $iptflush, $flushline);
  my $logger = Log::Log4perl->get_logger('firewalld.reload.dns');
  if (! Log::Log4perl::initialized()) { $logger->warn("uninit"); }

  my $sql = "UPDATE vars_num SET value=? WHERE name=?";
  my $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute(0,'fw_reload_dns');

  $sql = "SELECT hostname, ip FROM hostnames_current";
  $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute();
  $sth->bind_columns(\$hostname, \$ip);
  while ($sth->fetch()) {
    push(@replacedns,[ "dns-$hostname", "$ip" ] );
  }
  push(@replacedns,[ "^-A ", "-A dns-" ] );

  if ( -e $heap->{datapath}."/ipt_update" ) {
    unlink $heap->{datapath}."/ipt_update" or $logger->warn("Could not unlink ".$heap->{datapath}."/ipt_update: $!");
  }
  if ( ! open($iptupdate, ">", $heap->{datapath}."/ipt_update")) { $logger->fatal("cannot open < ".$heap->{datapath}."/ipt_update: $!"); exit 1;};
  if ( ! opendir($dh, $heap->{datapath}) ) { $logger->fatal("can't opendir ".$heap->{datapath}.": $!\n"); exit 1; };
  my @files = grep { /^dns-/ && -f $heap->{datapath}."/$_" } readdir($dh);
  closedir $dh;
  foreach my $file (@files) {
    $table = $file;
    $table =~ s/^dns-//;
    if (! open($iptflush, "iptables-save -t $table |")) { $logger->fatal("cannot open iptables-save -t $table |: $!"); exit 1};
    foreach $flushline (<$iptflush>) {
      if ($flushline =~ m/^:dns-([^ ]*) /) {
        print $iptupdate "iptables -t $table -F $1\n";
      }
    }
    close($iptflush);
    if ( ! open($fh, "<", $heap->{datapath}."/$file")) { $logger->fatal("cannot open < ".$heap->{datapath}."/$file: $!"); exit 1};
    foreach $line (<$fh>) {
      foreach my $replace (@replacedns) {
        $line =~ s/$replace->[0]/$replace->[1]/g;
      }
      if ( $line =~ m/[sd] dns-/ ) {
        # warn "Unknown dns-reference: iptables -t $table $line";
        next;
      }
      print $iptupdate "iptables -t $table ".$line;
    }
    close($fh);
  }
  close ($iptupdate);
  chmod 0555, $heap->{datapath}."/ipt_update";
  system($heap->{datapath}."/ipt_update");
}

=head2 firewall_find_dnsnames

checks the firewall config groups/hostname-* for dns-names and adds syncs them with the list of names to be checked
=cut
sub firewall_find_dnsnames {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
  if (! Log::Log4perl::initialized()) { DEBUG "firewall_find_dnsnames: uninit"; } else { DEBUG "firewall_find_dnsnames: init"; }
  my $line;
  my $fh;
  my $hostname;
  my $sql = "DELETE FROM hostnames";
  my $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute();
  $sql = "INSERT INTO hostnames (hostname) VALUES (?)";
  $sth = $heap->{dbh}->prepare("$sql");
  opendir(my $dh, $cfg->find('config/@path')."/groups") || die "can't opendir ".$cfg->find('config/@path')."/groups: $!\n";
  my @files = grep { /^hostgroup-/ && -f $cfg->find('config/@path')."/groups/$_" } readdir($dh);
  closedir $dh;
  foreach my $file (@files) {
    open($fh, "<", $cfg->find('config/@path')."/groups/$file") or die "cannot open < ".$cfg->find('config/@path')."/groups/$file: $!";
    foreach $line (<$fh>) {
      $line =~ m/dns-/ || next;
      $line =~ s/^dns-//;
      chop $line;
      $sth->execute($line);
      # $kernel->yield("dns_query", 'A', $line);
    }
    close($fh);
  }
  $sql = "DELETE FROM hostnames_current WHERE hostnames_current.hostname NOT IN (SELECT hostname FROM hostnames)";
  $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute();
  $sql = "SELECT hostnames.hostname FROM hostnames WHERE hostname NOT IN (SELECT hostname FROM hostnames_current)";
  $sth = $heap->{dbh}->prepare("$sql");
  $sth->execute();
  $sth->bind_columns(\$hostname);
  while ( $sth->fetch ) {
    $kernel->yield("dns_query", 'A', $hostname);
  }
  $kernel->delay('firewall_find_dnsnames', $heap->{refresh_dns_config});
}

=head2 firewall_create_db

Setup the db according to the config.xml
=cut
sub firewall_create_db {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  if (! Log::Log4perl::initialized()) { DEBUG "firewall_create_db: uninit"; } else { DEBUG "firewall_create_db: init"; }
  foreach my $sql (split(/;/,$cfg->find('database/create'))) {
    if ( defined $sql ) {
      chomp $sql;
      $sql =~ s/\n//g;
      $heap->{dbh}->do("$sql");
    }
  }
}

sub session_default {
  my ($event, $args) = @_[ARG0, ARG1];
  if (! Log::Log4perl::initialized()) { DEBUG "session_default: uninit"; } else { DEBUG "session_default: init"; }
  ERROR( "Session ", $_[SESSION]->ID, " caught unhandled event $event with (@$args).\n");
}

sub session_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  if (! Log::Log4perl::initialized()) { DEBUG "session_start: uninit"; } else { DEBUG "session_start: init"; }
  $heap->{dbh} = DBI->connect($cfg->find('database/dbd/@connectorstring'));
  $heap->{datapath} = $cfg->find('config/@db_dbd');

  # fw dns-rules need a reload for initially
  my $sql = "DELETE FROM vars_num WHERE name=?";
  my $sth = $heap->{dbh}->prepare($sql);
  $sth->execute('fw_reload_dns');
  $sql = "INSERT INTO vars_num (name, value) VALUES (?,?)";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute('fw_reload_dns', 1);

  $heap->{refresh_dns_config} = $cfg->find('dns/@refresh_dns_config');
  $heap->{refresh_dns_minimum} = $cfg->find('dns/@refresh_dns_minimum');
  firewall_create_db(@_);
  $kernel->yield('timer_ping');
  $kernel->yield('firewall_find_dnsnames');
  $kernel->yield('dns_update');
  $kernel->yield('firewall_reload_dns');
  return 0;
}

sub session_stop {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  DEBUG "session_stop\n";
  $heap->{dbh}->disconnect;
  return 0;
}

POE::Session->create(
  inline_states => {
    _start => \&session_start,
    _stop => \&session_stop,
    _default => \&session_default,
    timer_ping => \&LiHAS::Firewall::Ping::timer_ping,
    ping_client_start => \&LiHAS::Firewall::Ping::ping_client_start,
    client_send_ping => \&LiHAS::Firewall::Ping::client_send_ping,
    client_got_pong => \&LiHAS::Firewall::Ping::client_got_pong,
    dns_update => \&LiHAS::Firewall::DNS::dns_update,
    dns_query => \&LiHAS::Firewall::DNS::dns_query,
    dns_response => \&LiHAS::Firewall::DNS::dns_response,
    firewall_find_dnsnames => \&firewall_find_dnsnames,
    firewall_reload_dns => \&firewall_reload_dns,
  }
);

DEBUG "kernel-run\n";
POE::Kernel->run();

exit 0;
