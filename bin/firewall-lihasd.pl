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

sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::Ping Component::Client::DNS);
# use Test::More skip_all => "Derzeit keine Tests";
use lib "lib/";
use LiHAS::Firewall::Ping;
use LiHAS::Firewall::DNS;

sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions
sub TIMER_DELAY () { 10 }; # ping delay
sub DEBUG () { 1 }; # display more information

my $cfg = new XML::Application::Config("LiHAS-Firewall","config.xml");
my $dns  = LiHAS::Firewall::DNS->new($cfg);

my $i;

my @addresses;

sub session_default {
  my ($event, $args) = @_[ARG0, ARG1];
  print( "Session ", $_[SESSION]->ID, " caught unhandled event $event with (@$args).\n");
}

sub session_start {
    $_[KERNEL]->delay('timer_ping', 0);
    return 0;
}

sub session_stop {
    DEBUG && print "session_stop\n";
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
    dns_response => sub { $dns->ping_client_start },
  }
);


DEBUG && print "kernel-run\n";
POE::Kernel->run();

exit 0;
