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

# Requirements: libxml-application-config-perl

use warnings;
use strict;

use XML::Application::Config;

use POE qw(Component::Client::Ping Component::Client::DNS );
# use Test::More skip_all => "Derzeit keine Tests";
use lib "lib/";
use LiHAS::Firewall::Ping;
use LiHAS::Firewall::DNS;
use DBI;


sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions
sub TIMER_DELAY () { 10 }; # ping delay
sub DEBUG () { 1 }; # display more information

my $cfg = new XML::Application::Config("LiHAS-Firewall","config.xml");
my $dbh = DBI->connect($cfg->find('database/dbd/@connectorstring'));

my $i;

sub firewall_find_dnsnames {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
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

sub firewall_create_db {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
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
  print( "Session ", $_[SESSION]->ID, " caught unhandled event $event with (@$args).\n");
}

sub session_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $heap->{dbh} = $dbh;
  $heap->{refresh_dns_config} = $cfg->find('dns/@refresh_dns_config');
  $heap->{refresh_dns_minimum} = $cfg->find('dns/@refresh_dns_minimum');
  firewall_create_db(@_);
  $kernel->delay('timer_ping', 0);
  $kernel->delay('firewall_find_dnsnames', 0);
  $kernel->delay('dns_update', 0);
  return 0;
}

sub session_stop {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  DEBUG && print "session_stop\n";
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
  }
);

DEBUG && print "kernel-run\n";
POE::Kernel->run();

exit 0;
