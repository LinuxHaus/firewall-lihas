#!/usr/bin/perl
# Copyright (C) 2014 Adrian Reyer support@lihas.de
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

our $DEBUG=0;
use Log::Log4perl qw(:easy);
Log::Log4perl::init('/etc/firewall.lihas.d/log4perl.conf');
if (! Log::Log4perl::initialized()) { WARN "uninit"; } else { }

my $expand_hostgroups=0;
my $expand_portgroups=0;
my $do_shaping=0;
use Getopt::Mixed;
my ($option, $value);
Getopt::Mixed::init("H P s d expand-hostgroup>H expand-portgroup>P shaping>s debug>d");
while (($option, $value) = Getopt::Mixed::nextOption()) {
	if ($option=~/^H$/) {
		$expand_hostgroups=1;
	} elsif ($option=~/^d$/) {
		$DEBUG=1;
	} elsif ($option=~/^P$/) {
		$expand_portgroups=1;
	} elsif ($option=~/^s$/) {
		$do_shaping=1;
	}
}
Getopt::Mixed::cleanup();

=head1 NAME
firewall-lihas.pl

replace shell fragments of firewall.sh and eventually the whole firewall.sh.
=cut

use warnings;
use strict;

$SIG{__WARN__} = sub {
  local $Log::Log4perl::caller_depth =
        $Log::Log4perl::caller_depth + 1;
  WARN @_;
};

use XML::Application::Config;
# use Test::More skip_all => "Derzeit keine Tests";
use lib "/etc/firewall.lihas.d/lib";

my $cfg = new XML::Application::Config("LiHAS-Firewall","/etc/firewall.lihas.d/config.xml");

our %hostgroup;
our %portgroup;

=head1 Functions

=head2 parse_hostgroup

Goal: load every hostgroup file only once

=cut

sub parse_hostgroup {
	my ($arg_ref) = @_;
	my $path = $arg_ref->{path};
	my $name = $arg_ref->{name};
	if (!defined ${$hostgroup{$name}}{defined}) {
		${$hostgroup{$name}}{defined}=1;
		${$hostgroup{$name}}{hosts}=[];
		open(my $fh, "<", $path."/groups/hostgroup-".$name) or die "cannot open < ".$path."/groups/hostgroup-".$name.": $!";
		foreach my $line (<$fh>) {
			chop $line;
			$line =~ m/^#/ && next;
			$line =~ m/^[ \t]*$/ && next;
			if ( $line =~ m/^hostgroup-([^ ]*)(|[ \t]*#.*)$/ ) {
				if (!defined $hostgroup{$1}{defined}) {
					parse_hostgroup({path=>$path, name=>$1});
				} else {
				}
				foreach (values(@{$hostgroup{$1}{hosts}})) {
					push(@{$hostgroup{$name}}{hosts}, $_);
				}
			} elsif ( $line =~ m/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(|\/[0-9]+)|dns-[a-zA-Z0-9-\.]+)/){
				my $host = $1;
				push(@{$hostgroup{$name}}{hosts}, $host);
			}
		}
		close($fh);
	}
}

=head2 expand_hostgroup

Goal: load every hostgroup file only once
=cut

sub expand_hostgroup {
	my $line = $_[0];
	my $replaceline='';
	my $resultline='';
	my $name = $line;
	if ( $line =~ m/hostgroup-([a-zA-Z0-9_\.-]+)\b/ ) {
		my $name = $1;
		if (!defined ${$hostgroup{$name}}{defined}) {
			WARN "Hostgroup $name undefined, '$line' dropped\n";
			$line = "";
		} else {
			foreach my $replacement (values(${$hostgroup{$name}}{hosts})) {
				$replaceline = $line;
				$replaceline =~ s/hostgroup-$name\b/$replacement/;
				$resultline .= expand_hostgroup($replaceline);
			}
			$line = $resultline;
		}
	}
	return $line;
}

=head2 parse_portgroup

Goal: load every portgroup file only once
=cut

sub parse_portgroup {
	my ($arg_ref) = @_;
	my $path = $arg_ref->{path};
	my $name = $arg_ref->{name};
	if (!defined ${$portgroup{$name}}{defined}) {
		${$portgroup{$name}}{defined}=1;
		@{$portgroup{$name}}{ports}=[];
		open(my $fh, "<", $path."/groups/portgroup-".$name) or die "cannot open < ".$path."/groups/portgroup-".$name.": $!";
		foreach my $line (<$fh>) {
			chop $line;
			$line =~ m/^#/ && next;
			$line =~ m/^[ \t]*$/ && next;
			if ( $line =~ m/^(any|tcp|udp|icmp)[ \t]+portgroup-([^ ]*)(|[ \t])*(#.*|)$/ ) {
				my $tmpport = $2;
				my $tmpgrp = $2;
				if (!defined $portgroup{$tmpgrp}{defined}) {
					parse_portgroup({path=>$path, name=>$tmpgrp});
				} else {
				}
				foreach my $proto (keys(%{$portgroup{$tmpgrp}{proto}})) {
					foreach my $port (values(@{$portgroup{$tmpgrp}{proto}{$proto}{ports}})) {
					  push(@{$portgroup{$name}{proto}{$proto}{ports}}, $port);
					}
				}
			} elsif ( $line =~ m/^([a-zA-Z0-9]+)[ \t]+([0-9]+)/){
				my $proto = $1;
				my $port = $2;
				push(@{$portgroup{$name}{proto}{$proto}{ports}}, $port);
			}
		}
		close($fh);
		if ($DEBUG) {
			foreach my $proto (keys(%{$portgroup{$name}{proto}})) {
				foreach my $port (values(@{$portgroup{$name}{proto}{$proto}{ports}})) {
					DEBUG "portgroup $name: $proto $port";
				}
			}
		}
	}
}

=head2 expand_portgroup
=cut

sub expand_portgroup {
	my $line = $_[0];
	my $replaceline='';
	my $resultline='';
	my $name = $line;
	if ( $line =~ m/^(.*)[ \t]+(any|tcp|udp|icmp)[ \t]+portgroup-([a-zA-Z0-9_\.-]+)\b/ ) {
		my $base = $1;
		my $proto = $2;
		my $name = $3;
		if (!defined ${$portgroup{$name}}{defined}) {
			WARN "Portgroup $name undefined, '$line' dropped\n";
			$line = "";
		} else {
			if ($proto =~ /^any$/) {
				foreach $proto (keys %{$portgroup{$name}{proto}}) {
					foreach my $port (values @{$portgroup{$name}{proto}{$proto}{ports}}) {
						$resultline .= "$base\t$proto\t$port\n";
					}
				}
			} else {
				foreach my $port (values @{$portgroup{$name}{proto}{$proto}{ports}}) {
					$resultline .= "$base\t$proto\t$port\n";
				}
			}
		}
	} else {
	}
	return $resultline;
}

=head2 do_shaping
=cut

sub do_shaping {
	
}

=head2 main stuff
=cut

if ($expand_hostgroups) {
  opendir(my $dh, $cfg->find('config/@path')."/groups") || die "can't opendir ".$cfg->find('config/@path')."/groups: $!\n";
  my @files = grep { /^hostgroup-/ && -f $cfg->find('config/@path')."/groups/$_" } readdir($dh);
  closedir $dh;
  my $path = $cfg->find('config/@path');
  foreach my $file (@files) {
  	my $name = $file;
  	$name =~ s/^hostgroup-//;
		parse_hostgroup({path=>$path, name=>$name});
  }
}
if ($expand_portgroups) {
  opendir(my $dh, $cfg->find('config/@path')."/groups") || die "can't opendir ".$cfg->find('config/@path')."/groups: $!\n";
  my @files = grep { /^portgroup-/ && -f $cfg->find('config/@path')."/groups/$_" } readdir($dh);
  closedir $dh;
  my $path = $cfg->find('config/@path');
  foreach my $file (@files) {
  	my $name = $file;
  	$name =~ s/^portgroup-//;
		parse_portgroup({path=>$path, name=>$name});
  }
}

if ($expand_hostgroups) {
	foreach my $line (<>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		if ($expand_portgroups) {
			foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
				$line1.="\n";
				print expand_portgroup($line1);
			}
		} else {
			print expand_hostgroup($line);
		}
	}
} elsif ($expand_hostgroups) {
	foreach my $line (<>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		print expand_portgroup($line);
	}
}

# vim: ts=2 sw=2 sts=2 sr noet
exit 0;
