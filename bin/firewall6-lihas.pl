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
use DBI;

my $expand_hostgroups=0;
my $expand_portgroups=0;
my $fw_privclients=0;
my $do_shaping=0;
my $TARGETLOG="LOG";
our $do_comment=$ENV{'HAVE_COMMENT'};
our %policymark;
my $CONNSTATE=$ENV{'CONNSTATE'};
use Getopt::Long qw(GetOptions);
Getopt::Long::Configure qw(gnu_getopt);
GetOptions(
	'expand-hostgroup|H' => \$expand_hostgroups,
	'log|l=s' => \$TARGETLOG,
	'debug|d' => \$DEBUG,
	'expand-portgroup|P' => \$expand_portgroups,
  'firewall|f' => \$fw_privclients,
  'shaping|s' => \$do_shaping,
	'comment|v' => \$do_comment,
	'conntrack|c' => \$do_conntrack
) or ERROR "Unknown Option\n";
if ($do_conntrack) { WARN "Connection tracking synchronization is not yet implemented"; }
if ($do_comment) { WARN "Comments are not yet fully implemented"; }

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

use IO::Handle;
my $FILE = IO::Handle->new();
my $FILEfilter = IO::Handle->new();
my $FILEnat = IO::Handle->new();
my $FILEmangle = IO::Handle->new();
my $FILEraw = IO::Handle->new();
# exec 4>$FILE 5>$FILEfilter 6>$FILEnat 7>$FILEmangle 8>$FILEraw 9>$FILE6 10>$FILE6filter 11>$FILE6nat 12>$FILE6mangle 13>$FILE6raw
$FILE->fdopen(9,"w");
$FILEfilter->fdopen(10,"w");
$FILEnat->fdopen(11,"w");
$FILEmangle->fdopen(12,"w");
$FILEraw->fdopen(13,"w");

use XML::Application::Config;
# use Test::More skip_all => "Derzeit keine Tests";
use lib "/etc/firewall.lihas.d/lib";

my $cfg = new XML::Application::Config("LiHAS-Firewall","/etc/firewall.lihas.d/config.xml");
my $configpath = $cfg->find('config/@path');

our %hostgroup;
our %portgroup;
our %ifacegroup;
our $nextcommentid=1;
my $commentchain;

=head1 Functions

=head2 parse_policies

=cut

sub parse_policies {
}

=head2 parse_ifacegroup

Goal: load every ifacegroup file only once

=cut

sub parse_ifacegroup {
	my ($arg_ref) = @_;
	my $path = $arg_ref->{path};
	my $name = $arg_ref->{name};
	my $dbh = $arg_ref->{dbh};
	if (!defined ${$ifacegroup{$name}}{defined}) {
		${$ifacegroup{$name}}{defined}=1;
		${$ifacegroup{$name}}{ifaces}=[];
		open(my $fh, "<", $path."/groups/ifacegroup-".$name) or die "cannot open < ".$path."/groups/ifacegroup-".$name.": $!";
		$ifacegroup{$name}{comment} = firewall_comment_add_key($dbh,"groups/ifacegroup-".$name);
		foreach my $line (<$fh>) {
			chop $line;
			$line =~ m/^#/ && next;
			$line =~ m/^[ \t]*$/ && next;
			if ( $line =~ m/^ifacegroup-([^ ]*)(|[ \t]*#.*)$/ ) {
				if (!defined $ifacegroup{$1}{defined}) {
					parse_ifacegroup({path=>$path, name=>$1, dbh=>$dbh});
				} else {
				}
				foreach my $iface (values(@{$ifacegroup{$1}{ifaces}})) {
					push(@{$ifacegroup{$name}{ifaces}}, $iface);
				}
			} elsif ( $line =~ m/^(.*)$/){
				my $iface = $1;
				push(@{$ifacegroup{$name}{ifaces}}, $iface);
			}
		}
		close($fh);
	}
}

=head2 parse_hostgroup

Goal: load every hostgroup file only once

=cut

sub parse_hostgroup {
	my ($arg_ref) = @_;
	my $path = $arg_ref->{path};
	my $name = $arg_ref->{name};
	my $dbh = $arg_ref->{dbh};
	if (!defined ${$hostgroup{$name}}{defined}) {
		${$hostgroup{$name}}{defined}=1;
		${$hostgroup{$name}}{hosts}=[];
		open(my $fh, "<", $path."/groups/hostgroup6-".$name) or die "cannot open < ".$path."/groups/hostgroup6-".$name.": $!";
		$hostgroup{$name}{comment} = firewall_comment_add_key($dbh,"groups/hostgroup6-".$name);
		foreach my $line (<$fh>) {
			chop $line;
			$line =~ m/^#/ && next;
			$line =~ m/^[ \t]*$/ && next;
			if ( $line =~ m/^hostgroup-([^ ]*)(|[ \t]*#.*)$/ ) {
				if (!defined $hostgroup{$1}{defined}) {
					parse_hostgroup({path=>$path, name=>$1, dbh=>$dbh});
				} else {
				}
				foreach my $host (values(@{$hostgroup{$1}{hosts}})) {
					push(@{$hostgroup{$name}{hosts}}, $host);
				}
			} elsif ( $line =~ m/^((([0-9:]+)(|\/[0-9]+))|dns-[a-zA-Z0-9-\.]+)(\s.*|)$/){
				my $host = $1;
				push(@{$hostgroup{$name}{hosts}}, $host);
			}
		}
		close($fh);
	}
}

=head2 expand_ifacegroup

Goal: load every ifacegroup file only once
=cut

sub expand_ifacegroup {
	my ($arg_ref) = @_;
	my $line = $arg_ref->{line};
	my $dbh = $arg_ref->{dbh};
	my $replaceline='';
	my $resultline='';
	my $name = $line;
	if ( $line =~ m/ifacegroup-([a-zA-Z0-9_\.-]+)\b/ ) {
		my $name = $1;
		$commentchain .= " " . firewall_comment_add_key($dbh,"groups/".$name);
		if (!defined ${$ifacegroup{$name}}{defined}) {
			WARN "Ifacegroup $name undefined, '$line' dropped\n";
			$line = "";
		} else {
			foreach my $replacement (values(@{${$ifacegroup{$name}}{ifaces}})) {
				$replaceline = $line;
				$replaceline =~ s/ifacegroup-$name\b/$replacement/;
				$resultline .= expand_ifacegroup({dbh=>$dbh, line=>$replaceline}) . "\n";
			}
			$line = $resultline;
		}
	}
	return $line;
}

=head2 expand_hostgroup

Goal: load every hostgroup file only once
=cut

sub expand_hostgroup {
	my ($arg_ref) = @_;
	my $line = $arg_ref->{line};
	my $dbh = $arg_ref->{dbh};
	my $replaceline='';
	my $resultline='';
	my $name = $line;
	if ( $line =~ m/hostgroup-([a-zA-Z0-9_\.-]+)\b/ ) {
		my $name = $1;
		$commentchain .= " " . firewall_comment_add_key($dbh,"groups/".$name);
		if (!defined ${$hostgroup{$name}}{defined}) {
			WARN "Hostgroup $name undefined, '$line' dropped\n";
			$line = "";
		} else {
			foreach my $replacement (values(@{${$hostgroup{$name}}{hosts}})) {
				$replaceline = $line;
				$replaceline =~ s/hostgroup-$name\b/$replacement/;
				$resultline .= expand_hostgroup({dbh=>$dbh, line=>$replaceline});
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
	my $dbh = $arg_ref->{dbh};
	if (!defined ${$portgroup{$name}}{defined}) {
		${$portgroup{$name}}{defined}=1;
		@{$portgroup{$name}}{ports}=[];
		open(my $fh, "<", $path."/groups/portgroup-".$name) or die "cannot open < ".$path."/groups/portgroup-".$name.": $!";
		$portgroup{$name}{comment} = firewall_comment_add_key($dbh,"groups/portgroup-".$name);
		foreach my $line (<$fh>) {
			chop $line;
			$line =~ m/^#/ && next;
			$line =~ m/^[ \t]*$/ && next;
			if ( $line =~ m/^icmp\W/ ) {
				INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
				$line =~ s/^icmp/ipv6-icnp/;
			}
			if ( $line =~ m/^(any|tcp|udp|ipv6-icmp)[ \t]+portgroup-([^ ]*)(|[ \t])*(#.*|)$/ ) {
				my $tmpproto = $1;
				my $tmpgrp = $2;
				if (!defined $portgroup{$tmpgrp}{defined}) {
					parse_portgroup({path=>$path, name=>$tmpgrp, dbh=>$dbh});
				} else {
				}
				foreach my $proto (keys(%{$portgroup{$tmpgrp}{proto}})) {
					foreach my $port (values(@{$portgroup{$tmpgrp}{proto}{$proto}{ports}})) {
					  push(@{$portgroup{$name}{proto}{$proto}{ports}}, $port);
					}
				}
			} elsif ( $line =~ m/^([a-zA-Z0-9]+)[ \t]+([0-9:]+)/){
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
	my ($arg_ref) = @_;
	my $line = $arg_ref->{line};
	my $dbh = $arg_ref->{dbh};
	my $replaceline='';
	my $resultline='';
	my $name = $line;
	if ( $line =~ m/^(.*)[ \t]+(any|tcp|udp|ipv6-icmp)[ \t]+portgroup-([a-zA-Z0-9_\.-]+)\b/ ) {
		my $base = $1;
		my $proto = $2;
		my $name = $3;
		$commentchain .= " " . firewall_comment_add_key($dbh,"groups/".$name);
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
		$resultline = $line;
	}
	return $resultline;
}

=head2 fw_mark

fw_mark($dbh, $iface, $startpath, $commentchain)

set special rules for features, e.g. dhcpd, natreflect
=cut

sub fw_mark {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $markfile, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$markfile>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_mark($dbh, $iface, "$configpath/$1",$commentchain);
		} elsif ($line =~ /^dhcpd/) {
			print $FILEfilter "-A INPUT -i $iface -p udp --sport 68 --dport 67 -j ACCEPT\n";
			print $FILEfilter "-A OUTPUT -o $iface -p udp --sport 67 --dport 68 -j ACCEPT\n";
		} elsif ($line =~ /^natreflect/) {
			print $FILEmangle "-A FORWARD -i $iface -o $iface -j CONNMARK --set-xmark 0x80000000/0x80000000\n";
		}
	}
	close $markfile;
}

=head2 fw_nonat

fw_nonat($dbh, $iface, $startpath, $commentchain);

=cut

sub fw_nonat {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $nonat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$nonat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_nonat($dbh, $iface, "$configpath/$1",$commentchain);
		} else {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						my ($snet, $dnet, $proto, $dport) = split(/[\s]+/, $line3);
						$outline = "";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						if ( $snet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 src";
						} else {
							$outline .= " -s $snet";
						}
						if ( $dnet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 dst";
						} else {
							$outline .= " -d $dnet";
						}
						if ( $dport =~ /^0$/ ) {
							$outline .= " -p $proto";
						} else {
							if ( $proto =~ m/^icmp$/ ) {
								INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
								$proto =~ s/^icmp$/ipv6-icmp/;
							}
							if ( $proto =~ /^ipv6-icmp$/ ) {
								$outline .= " -p $proto --icmpv6-type $dport";
							} else {
								$outline .= " -p $proto --dport $dport";
							}
						}
						print $FILEnat "-A post-$iface $outline -j ACCEPT\n";
						print $FILEnat "-A pre-$iface $outline -j ACCEPT\n";
					}
				}
			}
		}
	}
	close $nonat;
}

=head2 fw_dnat
=cut

sub fw_dnat {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $dnat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$dnat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_dnat($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						my ($dnet, $mnet, $proto, $dport, $ndport) = split(/[\s]+/, $line3);
						$outline = "-A pre-$iface";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						if ($dnet =~ /^ACCEPT$/) {
							if ( $mnet =~ m/ipset-(.*)/ ) {
								$outline .= " -m set --match-set $1 src";
							} else {
								$outline .= " -s $mnet";
							}
							if ($dport =~ /^0$/ ) {
								print $FILEnat "$outline -p $proto -j ACCEPT\n";
							} else {
								if ( $proto =~ m/^icmp$/ ) {
									INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
									$proto =~ s/^icmp$/ipv6-icmp/;
								}
								if ( $proto =~ /^ipv6-icmp$/ ) {
									print $FILEnat "$outline -p $proto --icmpv6-type $dport -j ACCEPT\n";
								} else {
									print $FILEnat "$outline -p $proto --dport $dport -j ACCEPT\n";
								}
							}
						} else {
							if ( $dnet =~ m/^ipset-(.*)/ ) {
								$outline .= " -m set --match-set $1 dst";
							} else {
								$outline .= " -d $dnet";
							}
							if ( $mnet =~ m/^jump-(.*)/ ) {
								print $FILEnat "$outline -j $1\n";
							} elsif ( $dport =~ /^0$/ ) {
								print $FILEnat "$outline -p $proto -j DNAT --to-destination $mnet\n";
							} else {
								$ndport =~ s/:/-/g;
								if ( $proto =~ m/^icmp$/ ) {
									INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
									$proto =~ s/^icmp$/ipv6-icmp/;
								}
								if ( $proto =~ /^ipv6-icmp$/ ) {
									print $FILEnat "$outline -p $proto --icmpv6-type $dport -j DNAT --to-destination $mnet:$ndport\n";
								} else {
									print $FILEnat "$outline -p $proto --dport $dport -j DNAT --to-destination $mnet:$ndport\n";
								}
							}
		  			}
					}
		  	}
		  }
		}
	}
	close $dnat;
}

=head2 fw_snat
=cut

sub fw_snat {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $snat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$snat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_snat($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						my ($snet, $mnet, $proto, $dport) = split(/[\s]+/, $line3);
						$outline = "-A post-$iface";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						if ($snet =~ /^ACCEPT$/) {
							if ( $mnet =~ m/ipset-(.*)/ ) {
								$outline .= " -m set --match-set $1 src";
							} else {
								$outline .= " -s $mnet";
							}
							if ($dport =~ /^0$/ ) {
								print $FILEnat "$outline -p $proto -j ACCEPT\n";
							} else {
								if ( $proto =~ m/^icmp$/ ) {
									INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
									$proto =~ s/^icmp$/ipv6-icmp/;
								}
								if ( $proto =~ /^ipv6-icmp$/ ) {
									print $FILEnat "$outline -p $proto --icmpv6-type $dport -j ACCEPT\n";
								} else {
									print $FILEnat "$outline -p $proto --dport $dport -j ACCEPT\n";
								}
							}
						} else {
							if ( $snet =~ m/ipset-(.*)/ ) {
								$outline .= " -m set --match-set $1 src";
							} else {
								$outline .= " -s $snet";
							}
							if ( $dport =~ /^0$/ ) {
								print $FILEnat "$outline -p $proto -j SNAT --to-source $mnet\n";
							} else {
								if ( $proto =~ m/^icmp$/ ) {
									INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
									$proto =~ s/^icmp$/ipv6-icmp/;
								}
								if ( $proto =~ /^ipv6-icmp$/ ) {
									print $FILEnat "$outline -p $proto --icmpv6-type $dport -j SNAT --to-source $mnet\n";
								} else {
									print $FILEnat "$outline -p $proto --dport $dport -j SNAT --to-source $mnet\n";
								}
							}
						}
					}
				}
			}
		}
	}
	close $snat;
}

=head2 fw_masquerade
=cut

sub fw_masquerade {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $masquerade, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$masquerade>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_masquerade($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						$outline = "-A post-$iface";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
		  			my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line3);
						if ( $snet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 src";
						} else {
							$outline .= " -s $snet";
						}
		  			if ( $dport !~ /^0$/ ) {
							if ( $proto =~ m/^icmp$/ ) {
								INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
								$proto =~ s/^icmp$/ipv6-icmp/;
							}
		  				if ( $proto =~ /^ipv6-icmp$/ ) {
		  					$outline .= " -p $proto --icmpv6-type $dport";
		  				} else {
		  					$outline .= " -p $proto --dport $dport";
		  				}
		  			}
		  			if ( defined($oiface) && $oiface !~ /^$/ ) {
		  				print $FILEnat "$outline -o $oiface -j MASQUERADE\n";
		  			} else {
		  				print $FILEnat "$outline -j MASQUERADE\n";
		  			}
		  		}
				}
		  }
		}
	}
	close $masquerade;
}

=head2 fw_nologclients
=cut

sub fw_nologclients {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $nologclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$nologclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_nologclients($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						$outline = "$CONNSTATE NEW";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line3);
						if ( $snet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 src";
						} else {
							$outline .= " -s $snet";
						}
						if ( $dnet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 dst";
						} else {
							$outline .= " -d $dnet";
						}
						$outline .= " -p $proto";
						if ( $dport !~ /^0$/ ) {
							if ( $proto =~ m/^icmp$/ ) {
								INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
								$proto =~ s/^icmp$/ipv6-icmp/;
							}
							if ( $proto =~ /^ipv6-icmp$/ ) {
								$outline .= " --icmpv6-type $dport";
							} else {
								$outline .= " --dport $dport";
							}
						}
						if ( defined($oiface) && $oiface !~ /^$/ ) {
							print $FILEfilter "-A fwd-$iface $outline -o $oiface -j DROP\n";
						} else {
							print $FILEfilter "-A fwd-$iface $outline -j DROP\n";
						  print $FILEfilter "-A in-$iface $outline -j DROP\n";
						}
					}
				}
			}
		}
	}
	close $nologclients;
}

=head2 fw_rejectclients
=cut

sub fw_rejectclients {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $rejectclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$rejectclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_rejectclients($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						$outline = "$CONNSTATE NEW";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line3);
						if ( $snet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 src";
						} else {
							$outline .= " -s $snet";
						}
						if ( $dnet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 dst";
						} else {
							$outline .= " -d $dnet";
						}
						$outline .= " -p $proto";
						if ( $dport !~ /^0$/ ) {
							if ( $proto =~ m/^icmp$/ ) {
								INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
								$proto =~ s/^icmp$/ipv6-icmp/;
							}
							if ( $proto =~ /^ipv6-icmp$/ ) {
								$outline .= " --icmpv6-type $dport";
							} else {
								$outline .= " --dport $dport";
							}
						}
						if ( defined($oiface) && $oiface !~ /^$/ ) {
							print $FILEfilter "-A fwd-$iface $outline -o $oiface -j REJECT\n";
						} else {
							print $FILEfilter "-A fwd-$iface $outline -j REJECT\n";
						  print $FILEfilter "-A in-$iface $outline -j REJECT\n";
						}
					}
				}
			}
		}
	}
	close $rejectclients;
}

=head2 fw_privclients
=cut

sub fw_privclients {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $privclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$privclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_privclients($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
		  			my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line3);
		  			$outline = "$CONNSTATE NEW";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						if ( $snet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 src";
						} else {
							$outline .= " -s $snet";
						}
						if ( $dnet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 dst";
						} else {
							$outline .= " -d $dnet";
						}
						$outline .= " -p $proto";
		  			if ( $dport !~ /^0$/ ) {
							if ( $proto =~ m/^icmp$/ ) {
								INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
								$proto =~ s/^icmp$/ipv6-icmp/;
							}
		  				if ( $proto =~ /^ipv6-icmp$/ ) {
		  					$outline =~ s/$CONNSTATE NEW //;
		  					$outline .= " --icmpv6-type $dport";
		  				} else {
		  					$outline .= " --dport $dport";
		  				}
		  			}
		  			if ( defined($oiface) && $oiface =~ /^lo$/ ) {
		  				print $FILEfilter "-A in-$iface $outline -j ACCEPT\n";
		  			} elsif ( defined($oiface) && $oiface !~ /^$/ ) {
		  				print $FILEfilter "-A fwd-$iface $outline -o $oiface -j ACCEPT\n";
		  			} else {
		  				print $FILEfilter "-A fwd-$iface $outline -j ACCEPT\n";
		  			  print $FILEfilter "-A in-$iface $outline -j ACCEPT\n";
		  			}
		  		}
				}
		  }
		}
	}
	close $privclients;
}

=head2 fw_policyrouting
=cut

sub fw_policyrouting {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	my $commentchain = $_[3];
	my $outline = "";
	open(my $policyrouting, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$policyrouting>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_policyrouting($dbh, $iface, "$configpath/$1", $commentchain);
		} else {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					foreach my $line3 (split(/\n/,expand_ifacegroup({dbh=>$dbh, line=>$line2}))) {
						my ($snet, $dnet, $proto, $dport, $policy) = split(/[\s]+/, $line3);
						$outline = "";
						if ( $do_comment ) {
							$outline .= " -m comment --comment \"$commentchain\"";
						}
						if ( $snet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 src";
						} else {
							$outline .= " -s $snet";
						}
						if ( $dnet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 dst";
						} else {
							$outline .= " -d $dnet";
						}
						$outline .= " -p $proto";
						if ( $proto =~ m/^icmp$/ ) {
							INFO "icmp is no valid protocol for ipv6, using ipv6-icmp instead";
							$proto =~ s/^icmp$/ipv6-icmp/;
						}
						if ( $dport !~ /^0$/ ) {
							if ( $proto =~ /^ipv6-icmp$/ ) {
								$outline .= " --icmpv6-type $dport";
							} else {
								$outline .= " --dport $dport";
							}
						}
						$outline .= " -j MARK --set-mark $policymark{$policy}";
						print $FILEmangle "-A OUTPUT $outline\n";
						print $FILEmangle "-A PREROUTING $outline\n";
					}
				}
			}
		}
	}
	close $policyrouting;
}

=head2 do_shaping
=cut

sub do_shaping {
	
}

=head2 firewall_create_db

Setup the db according to the config.xml
TODO: Unify with firewall-lihasd.pl

=cut
sub firewall_create_db {
  my $dbh = $_[0];
	my $sql;
  foreach $sql (split(/;/,$cfg->find('database6/create'))) {
    if ( defined $sql ) {
      chomp $sql;
      $sql =~ s/\n//g;
      $dbh->do("$sql");
    }
  }
	$sql = "CREATE TABLE IF NOT EXISTS fw_comments ( id INTEGER NOT NULL, file TEXT NOT NULL, comment TEXT);";
  $dbh->do("$sql");
}

=head2 firewall_comment_add_key($dbh)

Add a commentindex/comment to the comment table, returns the commentindex used

=cut
sub firewall_comment_add_key {
	my $dbh = $_[0];
	my $file = $_[1];
	my $commentid=$nextcommentid;
	my $sql = "SELECT id FROM fw_comments WHERE file=?";
	my $sth = $dbh->prepare("$sql");
	$sth->execute($file);
  $sth->bind_columns(\$commentid);
	while ($sth->fetch()) {
		return $commentid;
	}
	$sql = "INSERT INTO fw_comments (id, file, comment) VALUES (?,?,'')";
	$sth = $dbh->prepare("$sql");
	$sth->execute($nextcommentid,$file);
	$nextcommentid++;
	return $commentid;
}

=head2 main stuff
=cut

my $dbh = DBI->connect($cfg->find('database6/dbd/@connectorstring'), { RaiseError => 1, AutoCommit => 1 });
if ($fw_privclients) {
	firewall_create_db($dbh);
}

if ($expand_hostgroups || $fw_privclients) {
  opendir(my $dh, "$configpath/groups") || die "can't opendir "."$configpath/groups: $!\n";
  my @files = grep { /^hostgroup6-/ && -f "$configpath/groups/$_" } readdir($dh);
  closedir $dh;
  my $path = $cfg->find('config/@path');
  foreach my $file (@files) {
  	my $name = $file;
  	$name =~ s/^hostgroup6-//;
		parse_hostgroup({path=>$path, name=>$name, dbh=>$dbh});
  }
}
if ($expand_portgroups || $fw_privclients) {
  opendir(my $dh, "$configpath/groups") || die "can't opendir "."$configpath/groups: $!\n";
  my @files = grep { /^portgroup-/ && -f "$configpath/groups/$_" } readdir($dh);
  closedir $dh;
  my $path = $cfg->find('config/@path');
  foreach my $file (@files) {
  	my $name = $file;
  	$name =~ s/^portgroup-//;
		parse_portgroup({path=>$path, name=>$name, dbh=>$dbh});
  }
}
my %comment;
if ($fw_privclients) {
	opendir(my $dh, "$configpath/groups") || die "can't opendir "."$configpath/groups: $!\n";
	my @files = grep { /^ifacegroup-/ && -f "$configpath/groups/$_" } readdir($dh);
	closedir $dh;
	my $path = $cfg->find('config/@path');
	foreach my $file (@files) {
		my $name = $file;
		$name =~ s/^ifacegroup-//;
		parse_ifacegroup({path=>$path, name=>$name, dbh=>$dbh});
	}
	opendir($dh, $cfg->find('config/@path')) || die "can't opendir "."$configpath: $!\n";
	my @interfaces = grep { /^interface-/ && -d "$configpath/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s "$configpath/$interfacedir/comment" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		$comment{$iface}=[];
		if ( -e "$configpath/$interfacedir/comment" ) {
			open(my $cf, "<", "$configpath/$interfacedir/comment") or die "cannot open < "."$configpath/$interfacedir/comment".": $!";
			foreach my $line (<$cf>) {
				push(@{$comment{$iface}}, $line);
			}
			close($cf);
		}
	}
	opendir($dh, $cfg->find('config/@path')) || die "can't opendir "."$configpath: $!\n";
	my @policies = grep { /^policy-routing-/ && -d "$configpath/$_/" } readdir($dh);
  foreach my $policydir (@policies) {
		-s "$configpath/$policydir/key" || next;
		my $policy = $policydir;
		$policy =~ s/^policy-routing-//;
		if ( -e "$configpath/$policydir/key" ) {
			open(my $cf, "<", "$configpath/$policydir/key6") or die "cannot open < "."$configpath/$policydir/key6".": $!";
			foreach my $line (<$cf>) {
				chop $line;
				$policymark{$policy}=$line;
			}
			close($cf);
		}
	}
}

my $dh;
my $commenthandle;
my @interfaces;
my @policies;

if ($fw_privclients) {
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir "."$configpath: $!\n";
  @interfaces = grep { /^interface-/ && -d "$configpath/$_/" } readdir($dh);
	@policies = grep { /^policy-routing-/ && -d "$configpath/$_/" } readdir($dh);
	closedir $dh;

	print "Setting up IPSEC Spoof Protection\n";
	foreach my $interfacedir (@interfaces) {
		-s "$configpath/$interfacedir/network6-ipsec" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
	  open(my $cf, "<", "$configpath/$interfacedir/network6-ipsec") or die "cannot open < "."$configpath/$interfacedir/network6-ipsec".": $!";
		foreach my $line (<$cf>) {
			chomp($line);
			$line =~ s/[ \t]*#.*//;
			$line =~ m/^[ \t]*$/ && next;
			print $FILEfilter "-A INPUT -s $line -i $iface -j in-$iface\n";
			print $FILEfilter "-A FORWARD -s $line -i $iface -j fwd-$iface\n";
			print $FILEfilter "-A INPUT -s $line -i $iface -j dns-in-$iface\n";
			print $FILEfilter "-A FORWARD -s $line -i $iface -j dns-fwd-$iface\n";
			print $FILEmangle "-A PREROUTING -p esp -j MARK --set-mark 8000/0000\n";
			print $FILEmangle "-A PREROUTING -p ah -j MARK --set-mark 8000/0000\n";
				print $FILEfilter "-A in-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j $TARGETLOG\n";
				print $FILEfilter "-A fwd-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j $TARGETLOG\n";
				print $FILEfilter "-A in-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j DROP\n";
				print $FILEfilter "-A fwd-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j DROP\n";
		}
		close($cf);
		print $FILEnat "-A PREROUTING -i $iface -j pre-$iface\n";
		print $FILEnat "-A POSTROUTING -o $iface -j post-$iface\n";
	}
  my %ifaces;
	print "Setting up Chains\n";
	foreach my $interfacedir (@interfaces) {
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		if ( -l "$configpath/$interfacedir" ) {
			$ifaces{physical}{$iface} = readlink "$configpath/$interfacedir";
			$ifaces{physical}{$iface} =~ s/^$configpath\///;
			$ifaces{physical}{$iface} =~ s/\/$//;
			if ($ifaces{physical}{$iface} =~ m/^interface-/) {
				$ifaces{physical}{$iface} =~ s/^interface-//;
			} else  {
				$ifaces{physical}{$iface}=$iface;
			}
			$ifaces{logical}{$ifaces{physical}{$iface}} = $ifaces{physical}{$iface};
		} else {
			$ifaces{physical}{$iface}=$iface;
			$ifaces{logical}{$iface}=$iface;
		}
	}
	foreach my $iface (keys(%{$ifaces{"physical"}})) {
		my $logicaliface = $ifaces{physical}{$iface};
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/network6" || next;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		if ( $iface =~ /^lo$/ ) {
      print $FILEfilter "-A OUTPUT -j fwd-$logicaliface\n";
      print $FILEnat "-A OUTPUT -j pre-$logicaliface\n";
      print $FILEnat "-A POSTROUTING -o $iface -j post-$logicaliface\n";
      print $FILEfilter "-A OUTPUT -j dns-fwd-$logicaliface\n";
      print $FILEnat "-A OUTPUT -j dns-pre-$logicaliface\n";
      print $FILEnat "-A POSTROUTING -o $iface -j dns-post-$logicaliface\n";
		} else {
			if ( -e "$configpath/$interfacedir/network6" ) {
				open(my $cf, "<", "$configpath/$interfacedir/network6") or die "cannot open < "."$configpath/$interfacedir/network6".": $!";
				foreach my $line (<$cf>) {
					chomp($line);
					$line =~ s/[ \t]*#.*//;
					$line =~ m/^[ \t]*$/ && next;
	        print $FILEfilter "-A INPUT -s $line -i $iface -j in-$logicaliface\n";
	        print $FILEfilter "-A FORWARD -s $line -i $iface -j fwd-$logicaliface\n";
	        print $FILEfilter "-A INPUT -s $line -i $iface -j dns-in-$logicaliface\n";
	        print $FILEfilter "-A FORWARD -s $line -i $iface -j dns-fwd-$logicaliface\n";
				}
				close($cf);
			} else {
	      print STDERR "WARNING: Interface $iface has no network6 file\n";
			}
	    print $FILEnat "-A PREROUTING -i $iface -j pre-$logicaliface\n";
	    print $FILEnat "-A POSTROUTING -o $iface -j post-$logicaliface\n";
	    print $FILEnat "-A PREROUTING -i $iface -j dns-pre-$logicaliface\n";
	    print $FILEnat "-A POSTROUTING -o $iface -j dns-post-$logicaliface\n";
		}
	}
	print "Loopback Interface is fine\n";
	print $FILEfilter "-A OUTPUT	-j ACCEPT -o lo\n";
	print $FILEfilter "-A INPUT		-j ACCEPT -i lo\n";
	if ( -x "$configpath/script6-pre" ) {
		print "Hook: script6-pre\n";
		system("$configpath/script6-pre");
	}
	print "Special rules (dhcpd, natreflection)\n";
	foreach my $iface (keys(%{$ifaces{"physical"}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/mark6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/mark6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_mark($dbh, $iface, "$configpath/$interfacedir/mark6", $commentchain);
	}
	print "Avoiding NAT\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/nonat6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/nonat6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_nonat($dbh, $iface, "$configpath/$interfacedir/nonat6",$commentchain);
	}
	print "Adding DNAT\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/dnat6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/dnat6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_dnat($dbh, $iface, "$configpath/$interfacedir/dnat6", $commentchain);
	}
	print "Adding SNAT\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/snat6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/snat6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_snat($dbh, $iface, "$configpath/$interfacedir/snat6", $commentchain);
	}
	print "Adding MASQUERADE\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/masquerade6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/masquerade6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_masquerade($dbh, $iface, "$configpath/$interfacedir/masquerade6", $commentchain);
	}
	print "Rejecting extra Clients\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/reject6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/reject6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_rejectclients($dbh, $iface, "$configpath/$interfacedir/reject6", $commentchain);
	}
	print "Adding priviledged Clients\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/privclients6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/privclients6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_privclients($dbh, $iface, "$configpath/$interfacedir/privclients6", $commentchain);
	}
	print "Disabling specific dropped connnection logs\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/nolog6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/nolog6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_nologclients($dbh, $iface, "$configpath/$interfacedir/nolog6", $commentchain);
	}
	print "Adding Policy Routing\n";
	foreach my $iface (keys(%{$ifaces{logical}})) {
		my $interfacedir="interface-$iface";
		-s "$configpath/$interfacedir/policy-routing6" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/policy-routing6");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_policyrouting($dbh, $iface, "$configpath/$interfacedir/policy-routing6", $commentchain);
	}
	print "Policy Routing routing setup";
	foreach my $policydir (@policies) {
		my $policy = $policydir;
		$policy =~ s/^policy-routing-//;
		-s "$configpath/policy-routing-$policy/key6" || next;
		-s "$configpath/policy-routing-$policy/gateway6" || next;
		foreach my $line (values(@{$comment{$policydir}})) {
			print "  ".$line;
		}
		my @cmd = ("ip", "route", "ls", "table", "$policy");
		if ( system(@cmd) != 0 ) {
			WARN "Please add '$policy' to /etc/iproute2/rt_tables or policy routing won't work. If you don't want policy routing, feel free to delete $configpath/policy-routing-$policy"
		}
		open(my $file, "<", "$configpath/policy-routing-$policy/key6") or die "cannot open < "."$configpath/policy-routing-$policy/key6".": $!";
		my $policykey=(<$file>);
		DEBUG "policykey: $policykey\n";
		close($file);
		open($file, "<", "$configpath/policy-routing-$policy/gateway6") or die "cannot open < "."$configpath/policy-routing-$policy/gateway6".": $!";
#INCOMPLETE#		foreach my $line (<$file>) {
#INCOMPLETE#			$line =~ s/[ \t]*#.*//;
#INCOMPLETE#			$line =~ m/^[ \t]*$/ && next;
#INCOMPLETE#			my ($type, $interface, $gateway) = split /[ \t]+/ $line;
#INCOMPLETE#			open();
#INCOMPLETE#			if ( $type == "PPP" ) {
#INCOMPLETE#			} elsif ( $type == "NET" ) {
#INCOMPLETE#			}
#INCOMPLETE#		}
		close($file);
	}

# natreflection, if conntrack bit 32 is set
	print $FILEnat "-A POSTROUTING -m connmark --mark 0x80000000/0x80000000 -j MASQUERADE\n";
} elsif ($expand_hostgroups) {
	foreach my $line (<>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		if ($expand_portgroups) {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				$line1.="\n";
				print expand_portgroup({dbh=>$dbh, line=>$line1});
			}
		} else {
			print expand_hostgroup({dbh=>$dbh, line=>$line});
		}
	}
} elsif ($expand_portgroups) {
	foreach my $line (<>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		print expand_portgroup({dbh=>$dbh, line=>$line});
	}
}

$FILE->close;
$FILEfilter->close;
$FILEnat->close;
$FILEmangle->close;

$dbh->disconnect or die $dbh->errstr;
exit 0;
# vim: ts=2 sw=2 sts=2 sr noet
