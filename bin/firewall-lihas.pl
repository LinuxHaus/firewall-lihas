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
my $fw_privclients=0;
my $do_shaping=0;
my $CONNSTATE=$ENV{'CONNSTATE'};
use Getopt::Mixed;
my ($option, $value);
Getopt::Mixed::init("H P s d f c=s conntrack>c firewall>f expand-hostgroup>H expand-portgroup>P shaping>s debug>d");
while (($option, $value) = Getopt::Mixed::nextOption()) {
	if ($option=~/^H$/) {
		$expand_hostgroups=1;
	} elsif ($option=~/^d$/) {
		$DEBUG=1;
	} elsif ($option=~/^P$/) {
		$expand_portgroups=1;
	} elsif ($option=~/^f$/) {
		$fw_privclients=1;
	} elsif ($option=~/^s$/) {
		$do_shaping=1;
	} elsif ($option=~/^c$/) {
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

use IO::Handle;
my $FILE = IO::Handle->new();
my $FILEfilter = IO::Handle->new();
my $FILEnat = IO::Handle->new();
my $FILEmangle = IO::Handle->new();
$FILE->fdopen(4,"w");
$FILEfilter->fdopen(5,"w");
$FILEnat->fdopen(6,"w");
$FILEmangle->fdopen(7,"w");

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
				foreach my $host (values(@{$hostgroup{$1}{hosts}})) {
					push(@{$hostgroup{$name}{hosts}}, $host);
				}
			} elsif ( $line =~ m/^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(|\/[0-9]+)|dns-[a-zA-Z0-9-\.]+)(\s.*|)$/){
				my $host = $1;
				push(@{$hostgroup{$name}{hosts}}, $host);
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
			foreach my $replacement (values(@{${$hostgroup{$name}}{hosts}})) {
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
		$resultline = $line;
	}
	return $resultline;
}

=head2 fw_nonat
=cut

sub fw_nonat {
	my $iface = $_[0];
	my $file = $_[1];
	open(my $nonat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$nonat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			fw_nonat($iface, $cfg->find('config/@path')."/$1");
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup($line1))) {
		  		my ($snet, $dnet, $proto, $dport) = split(/[\s]+/, $line2);
			    if ( $dport =~ /^0$/ ) {
			      print $FILEnat "-A post-$iface -s $snet -d $dnet -p $proto -j ACCEPT\n";
			    } else {
			      if ( $proto =~ /^icmp$/ ) {
			        print $FILEnat "-A post-$iface -s $snet -d $dnet -p $proto --icmp-type $dport -j ACCEPT\n";
			      } else {
			        print $FILEnat "-A post-$iface -s $snet -d $dnet -p $proto --dport $dport -j ACCEPT\n";
			      }
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
	my $iface = $_[0];
	my $file = $_[1];
	open(my $dnat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$dnat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			fw_dnat($iface, $cfg->find('config/@path')."/$1");
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup($line1))) {
		  		my ($dnet, $mnet, $proto, $dport, $ndport) = split(/[\s]+/, $line2);
					if ($dnet =~ /^ACCEPT$/) {
						if ($dport =~ /^0$/ ) {
							print $FILEnat "-A pre-$iface -s $mnet -p $proto -j ACCEPT\n";
						} else {
							if ( $proto =~ /^icmp$/ ) {
								print $FILEnat "-A pre-$iface -s $mnet -p $proto --icmp-type $dport -j ACCEPT\n";
							} else {
								print $FILEnat "-A pre-$iface -s $mnet -p $proto --dport $dport -j ACCEPT\n";
							}
						}
					} else {
			      if ( $dport =~ /^0$/ ) {
			        print $FILEnat "-A pre-$iface -d $dnet -p $proto -j DNAT --to-destination $mnet\n";
			      } else {
							$ndport =~ s/:/-/g;
			        if ( $proto =~ /^icmp$/ ) {
			          print $FILEnat "-A pre-$iface -d $dnet -p $proto --icmp-type $dport -j DNAT --to-destination $mnet:$ndport\n";
			        } else {
			          print $FILEnat "-A pre-$iface -d $dnet -p $proto --dport $dport -j DNAT --to-destination $mnet:$ndport\n";
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
	my $iface = $_[0];
	my $file = $_[1];
	open(my $snat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$snat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			fw_snat($iface, $cfg->find('config/@path')."/$1");
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup($line1))) {
		  		my ($snet, $mnet, $proto, $dport) = split(/[\s]+/, $line2);
					if ($snet =~ /^ACCEPT$/) {
						if ($dport =~ /^0$/ ) {
							print $FILEnat "-A post-$iface -s $snet -p $proto -j ACCEPT\n";
						} else {
							if ( $proto =~ /^icmp$/ ) {
								print $FILEnat "-A post-$iface -s $snet -p $proto --icmp-type $dport -j ACCEPT\n";
							} else {
								print $FILEnat "-A post-$iface -s $snet -p $proto --dport $dport -j ACCEPT\n";
							}
						}
					} else {
			      if ( $dport =~ /^0$/ ) {
			        print $FILEnat "-A post-$iface -s $snet -p $proto -j SNAT --to-source $mnet\n";
			      } else {
			        if ( $proto =~ /^icmp$/ ) {
			          print $FILEnat "-A post-$iface -s $snet -p $proto --icmp-type $dport -j SNAT --to-source $mnet\n";
			        } else {
			          print $FILEnat "-A post-$iface -s $snet -p $proto --dport $dport -j SNAT --to-source $mnet\n";
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
	my $iface = $_[0];
	my $file = $_[1];
	open(my $masquerade, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$masquerade>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			fw_masquerade($iface, $cfg->find('config/@path')."/$1");
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup($line1))) {
		  		my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line2);
		  		my $outline = "-s $snet -p $proto";
		  		if ( $dport !~ /^0$/ ) {
		  			if ( $proto =~ /^icmp$/ ) {
		  				$outline .= " --icmp-type $dport";
		  			} else {
		  				$outline .= " --dport $dport";
		  			}
		  		}
		  		if ( defined($oiface) && $oiface !~ /^$/ ) {
		  			print $FILEnat "-A post-$iface $outline -o $oiface -j MASQUERADE\n";
		  		} else {
		  			print $FILEnat "-A post-$iface $outline -j MASQUERADE\n";
		  		}
		  	}
		  }
		}
	}
	close $masquerade;
}

=head2 fw_rejectclients
=cut

sub fw_rejectclients {
	my $iface = $_[0];
	my $file = $_[1];
	open(my $rejectclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$rejectclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			fw_rejectclients($iface, $cfg->find('config/@path')."/$1");
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup($line1))) {
		  		my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line2);
		  		my $outline = "$CONNSTATE NEW -s $snet -d $dnet -p $proto";
		  		if ( $dport !~ /^0$/ ) {
		  			if ( $proto =~ /^icmp$/ ) {
		  				$outline .= " --icmp-type $dport";
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
	close $rejectclients;
}

=head2 fw_privclients
=cut

sub fw_privclients {
	my $iface = $_[0];
	my $file = $_[1];
	open(my $privclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$privclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			fw_privclients($iface, $cfg->find('config/@path')."/$1");
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup($line))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup($line1))) {
		  		my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line2);
		  		my $outline = "$CONNSTATE NEW -s $snet -d $dnet -p $proto";
		  		if ( $dport !~ /^0$/ ) {
		  			if ( $proto =~ /^icmp$/ ) {
		  				$outline .= " --icmp-type $dport";
		  			} else {
		  				$outline .= " --dport $dport";
		  			}
		  		}
		  		if ( defined($oiface) && $oiface !~ /^$/ ) {
		  			print $FILEfilter "-A fwd-$iface $outline -o $oiface -j ACCEPT\n";
		  		} else {
		  			print $FILEfilter "-A fwd-$iface $outline -j ACCEPT\n";
		  		  print $FILEfilter "-A in-$iface $outline -j ACCEPT\n";
		  		}
		  	}
		  }
		}
	}
	close $privclients;
}

=head2 do_shaping
=cut

sub do_shaping {
	
}

=head2 main stuff
=cut

if ($expand_hostgroups || $fw_privclients) {
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
if ($expand_portgroups || $fw_privclients) {
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
my %comment;
if ($fw_privclients) {
	opendir(my $dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
	my @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
  foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/comment" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		$comment{$iface}=[];
		if ( -e $cfg->find('config/@path')."/$interfacedir/comment" ) {
			open(my $cf, "<", $cfg->find('config/@path')."/$interfacedir/comment") or die "cannot open < ".$cfg->find('config/@path')."/$interfacedir/comment".": $!";
			foreach my $line (<$cf>) {
				push(@{$comment{$iface}}, $line);
			}
			close($cf);
		}
	}
}

my $dh;
my $commenthandle;
my @interfaces;
if ($fw_privclients) {
	print "Avoiding NAT\n";
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/nonat" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_nonat($iface, $cfg->find('config/@path')."/$interfacedir/nonat");
	}
	print "Adding DNAT\n";
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/dnat" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_dnat($iface, $cfg->find('config/@path')."/$interfacedir/dnat");
	}
	print "Adding SNAT\n";
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/snat" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_snat($iface, $cfg->find('config/@path')."/$interfacedir/snat");
	}
	print "Adding MASQUERADE\n";
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/masquerade" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_masquerade($iface, $cfg->find('config/@path')."/$interfacedir/masquerade");
	}
	closedir $dh;
	print "Rejecting extra Clients\n";
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/reject" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_rejectclients($iface, $cfg->find('config/@path')."/$interfacedir/reject");
	}
	closedir $dh;
	print "Adding priviledged Clients\n";
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/privclients" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_privclients($iface, $cfg->find('config/@path')."/$interfacedir/privclients");
	}
	closedir $dh;
} elsif ($expand_hostgroups) {
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
} elsif ($expand_portgroups) {
	foreach my $line (<>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		print expand_portgroup($line);
	}
}

$FILE->close;
$FILEfilter->close;
$FILEnat->close;
$FILEmangle->close;
# vim: ts=2 sw=2 sts=2 sr noet
exit 0;
