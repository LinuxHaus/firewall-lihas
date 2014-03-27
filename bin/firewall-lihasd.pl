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
  daemonize(root => root => '/var/run/firewall-lihasd.pid');
}

use Log::Log4perl qw(:easy);
Log::Log4perl::init('/etc/firewall.lihas.d/log4perl.conf');
if (! Log::Log4perl::initialized()) { WARN "uninit"; } else { WARN "init"; }

=head1 NAME

firewall-lihasd
Daemon supporting firewall-lihas by resolving dns-names

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
use LiHAS::Firewall::Portal;
use DBI;

my $cfg = new XML::Application::Config("LiHAS-Firewall","/etc/firewall.lihas.d/config.xml");

=head1 Functions

=head2 firewall_reload_dns

Reloads the iptables dns-* chains with current IPs from database
=cut
sub firewall_reload_dns {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];
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
      if ($flushline =~ m/^(:dns-[^ ]*) /) {
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
  foreach my $sql (split(/;/,$cfg->find('database/create'))) {
    if ( defined $sql ) {
      chomp $sql;
      $sql =~ s/\n//g;
      $heap->{dbh}->do("$sql");
    }
  }
}


use POE::Component::Server::TCP;
use XML::XPath;


sub session_default {
  my ($event, $args) = @_[ARG0, ARG1];
  ERROR( "Session ", $_[SESSION]->ID, " caught unhandled event $event with (@$args).\n");
}

=head2 
manage_server
paste xml-like stuff:
<application name="LiHAS-Firewall"><manage><feature><portal><cmd name="reload">reload</cmd></portal></feature></manage></application>
=cut

sub manage_server {
  POE::Component::Server::TCP->new(
    Address => '127.0.0.1',
    Port => 83,
    ClientConnected => sub {
      $_[HEAP]{client}->put("<application name=\"LiHAS-Firewall\"></application>");
      if (! Log::Log4perl::initialized()) { WARN "uninit"; } else { WARN "init"; }
    },

    ClientInput => sub {
      my ($sender, $kernel, $client_input) = @_[SESSION, KERNEL, ARG0];
      $kernel->post(firewalld => manage_server_got_line => $sender->postback('client_output'), $client_input);
    },

    InlineStates => {
      client_output => sub {
        my ($heap, $response) = @_[HEAP, ARG1];
        $heap->{client}->put($response->[0]) if defined $heap->{client};
            # that is, if $heap->{client} is still connected
        $_[KERNEL]->yield("shutdown");
      },
    },
  );
}

=head2
session_start
=cut
sub session_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $heap->{dbh} = DBI->connect($cfg->find('database/dbd/@connectorstring'));
  $heap->{datapath} = $cfg->find('config/@db_dbd');
  $heap->{configpath} = $cfg->find('config/@path');
  $heap->{portalname} = $cfg->find('/applicationconfig/application/feature/portal/name');

  firewall_create_db(@_);
  # fw dns-rules need a reload for initially

  $kernel->alias_set('firewalld');

  my $sql = "DELETE FROM vars_num WHERE name=?";
  my $sth = $heap->{dbh}->prepare($sql);
  $sth->execute('fw_reload_dns');
  $sql = "INSERT INTO vars_num (name, value) VALUES (?,?)";
  $sth = $heap->{dbh}->prepare($sql);
  $sth->execute('fw_reload_dns', 1);

  $heap->{refresh_dns_config} = $cfg->find('dns/@refresh_dns_config');
  $heap->{refresh_dns_minimum} = $cfg->find('dns/@refresh_dns_minimum');
  $heap->{feature_portal} = $cfg->find('feature/portal/@enabled');
  $kernel->yield('timer_ping');
  $kernel->yield('firewall_find_dnsnames');
  $kernel->yield('portal_init');
  $kernel->yield('portal_ipset_init');
  $kernel->yield('dns_update');
  $kernel->yield('firewall_reload_dns');
  manage_server();
  return 0;
}

sub session_stop {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  $heap->{dbh}->disconnect;
  return 0;
}

our $mainsession = POE::Session->create(
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
    portal_init => \&LiHAS::Firewall::Portal::portal_init,
    portal_ipset_init => \&LiHAS::Firewall::Portal::portal_ipset_init,
    firewall_find_dnsnames => \&firewall_find_dnsnames,
    firewall_reload_dns => \&firewall_reload_dns,
    manage_server_got_line => sub {
      my ($kernel, $heap, $postback, $client_input) = @_[KERNEL, HEAP, ARG0 .. $#_];
      # stash the postback on the heap
      $heap->{postback} = $postback;
      $kernel->yield(manage_server_eval_line => $client_input);
    },
    manage_server_eval_line => sub {
      my ($heap, $client_input) = @_[HEAP, ARG0 .. $#_];
      my $postback = $heap->{postback};
      my $client_output;

      my $request = XML::XPath->new(xml => $client_input);
      foreach my $cmd ( $request->findvalue('//cmd[@name]') ) {
        if ( $cmd =~ /^reload$/ ) {
	  $_[KERNEL]->yield('portal_ipset_init');
	  $client_output="<application name=\"LiHAS-Firewall\"><response>$cmd started</response></application>";
	} else {
	  $client_output="<application name=\"LiHAS-Firewall\"><response>Unknown command $cmd</response></application>";
        };
      }
      $postback->($client_output);
    },
  }
)->ID;

LiHAS::Firewall::Portal->http_redirector();

DEBUG "kernel-run\n";
POE::Kernel->run();
exit 0;
