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
use Getopt::Mixed;
my ($option, $value);
Getopt::Mixed::init("H P s d f v l=s c=s comment>v conntrack>c firewall>f expand-hostgroup>H expand-portgroup>P shaping>s log>l debug>d");
while (($option, $value) = Getopt::Mixed::nextOption()) {
	if ($option=~/^H$/) {
		$expand_hostgroups=1;
	} elsif ($option=~/^l$/) {
		$TARGETLOG=$value;
	} elsif ($option=~/^d$/) {
		$DEBUG=1;
	} elsif ($option=~/^P$/) {
		$expand_portgroups=1;
	} elsif ($option=~/^f$/) {
		$fw_privclients=1;
	} elsif ($option=~/^s$/) {
		$do_shaping=1;
		WARN "Shaping is not yet implemented";
	} elsif ($option=~/^v$/) {
		$do_comment=1;
		WARN "Comments are not yet fully implemented";
	} elsif ($option=~/^c$/) {
		$do_conntrack=1;
		WARN "Connection tracking synchronization is not yet implemented";
	} else {
		ERROR "Unknown Option $option\n";
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
our $nextcommentid=1;
our $commentchain;

=head1 Functions

=head2 parse_policies

=cut

sub parse_policies {
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
		open(my $fh, "<", $path."/groups/hostgroup-".$name) or die "cannot open < ".$path."/groups/hostgroup-".$name.": $!";
		$hostgroup{$name}{comment} = firewall_comment_add_key($dbh,"groups/hostgroup-".$name);
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
			if ( $line =~ m/^(any|tcp|udp|icmp)[ \t]+portgroup-([^ ]*)(|[ \t])*(#.*|)$/ ) {
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
	if ( $line =~ m/^(.*)[ \t]+(any|tcp|udp|icmp)[ \t]+portgroup-([a-zA-Z0-9_\.-]+)\b/ ) {
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

=head2 fw_nonat

fw_nonat($dbh $iface, $startpath, $commentchain);

=cut

sub fw_nonat {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	$commentchain = $_[3];
	my $outline = "";
	open(my $nonat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$nonat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_nonat($dbh, $iface, $cfg->find('config/@path')."/$1",$commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					my ($snet, $dnet, $proto, $dport) = split(/[\s]+/, $line2);
					$outline = "-A post-$iface";
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
			  	  print $FILEnat "$outline -p $proto -j ACCEPT\n";
			  	} else {
			  	  if ( $proto =~ /^icmp$/ ) {
			  	    print $FILEnat "$outline -p $proto --icmp-type $dport -j ACCEPT\n";
			  	  } else {
			  	    print $FILEnat "$outline -p $proto --dport $dport -j ACCEPT\n";
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
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	$commentchain = $_[3];
	my $outline = "";
	open(my $dnat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$dnat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_dnat($dbh, $iface, $cfg->find('config/@path')."/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
		  		my ($dnet, $mnet, $proto, $dport, $ndport) = split(/[\s]+/, $line2);
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
							if ( $proto =~ /^icmp$/ ) {
								print $FILEnat "$outline -p $proto --icmp-type $dport -j ACCEPT\n";
							} else {
								print $FILEnat "$outline -p $proto --dport $dport -j ACCEPT\n";
							}
						}
					} else {
						if ( $dnet =~ m/ipset-(.*)/ ) {
							$outline .= " -m set --match-set $1 dst";
						} else {
							$outline .= " -d $dnet";
						}
			      if ( $dport =~ /^0$/ ) {
			        print $FILEnat "$outline -p $proto -j DNAT --to-destination $mnet\n";
			      } else {
							$ndport =~ s/:/-/g;
			        if ( $proto =~ /^icmp$/ ) {
			          print $FILEnat "$outline -p $proto --icmp-type $dport -j DNAT --to-destination $mnet:$ndport\n";
			        } else {
			          print $FILEnat "$outline -p $proto --dport $dport -j DNAT --to-destination $mnet:$ndport\n";
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
	$commentchain = $_[3];
	my $outline = "";
	open(my $snat, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$snat>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_snat($dbh, $iface, $cfg->find('config/@path')."/$1", $commentchain);
		} else {
			foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
				foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					my ($snet, $mnet, $proto, $dport) = split(/[\s]+/, $line2);
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
							if ( $proto =~ /^icmp$/ ) {
								print $FILEnat "$outline -p $proto --icmp-type $dport -j ACCEPT\n";
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
							if ( $proto =~ /^icmp$/ ) {
								print $FILEnat "$outline -p $proto --icmp-type $dport -j SNAT --to-source $mnet\n";
							} else {
								print $FILEnat "$outline -p $proto --dport $dport -j SNAT --to-source $mnet\n";
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
	$commentchain = $_[3];
	my $outline = "";
	open(my $masquerade, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$masquerade>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_masquerade($dbh, $iface, $cfg->find('config/@path')."/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
					$outline = "-A post-$iface";
					if ( $do_comment ) {
						$outline .= " -m comment --comment \"$commentchain\"";
					}
		  		my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line2);
					if ( $snet =~ m/ipset-(.*)/ ) {
						$outline .= " -m set --match-set $1 src";
					} else {
						$outline .= " -p $proto -s $snet";
					}
		  		if ( $dport !~ /^0$/ ) {
		  			if ( $proto =~ /^icmp$/ ) {
		  				$outline .= " -p $proto --icmp-type $dport";
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
	close $masquerade;
}

=head2 fw_rejectclients
=cut

sub fw_rejectclients {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	$commentchain = $_[3];
	my $outline = "";
	open(my $rejectclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$rejectclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_rejectclients($dbh, $iface, $cfg->find('config/@path')."/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
		  		$outline = "$CONNSTATE NEW";
					if ( $do_comment ) {
						$outline .= " -m comment --comment \"$commentchain\"";
					}
		  		my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line2);
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
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	$commentchain = $_[3];
	my $outline = "";
	open(my $privclients, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$privclients>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_privclients($dbh, $iface, $cfg->find('config/@path')."/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
		  		my ($snet, $dnet, $proto, $dport, $oiface) = split(/[\s]+/, $line2);
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
		  			if ( $proto =~ /^icmp$/ ) {
		  				$outline .= " --icmp-type $dport";
		  			} else {
		  				$outline .= " --dport $dport";
		  			}
		  		}
		  		if ( defined($oiface) && $oiface !~ /^lo$/ ) {
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
	close $privclients;
}

=head2 fw_policyrouting
=cut

sub fw_policyrouting {
	my $dbh = $_[0];
	my $iface = $_[1];
	my $file = $_[2];
	$commentchain = $_[3];
	my $outline = "";
	open(my $policyrouting, "<", $file) or die "cannot open < $file: $!";
	foreach my $line (<$policyrouting>) {
		$line =~ m/^#/ && next;
		$line =~ m/^[ \t]*$/ && next;
		$line =~ s/#.*//;
		if ($line =~ /^include[\s]+([^\s]+)/) {
			$commentchain .= " " . firewall_comment_add_key($dbh,"$1");
			fw_policyrouting($dbh, $iface, $cfg->find('config/@path')."/$1", $commentchain);
		} else {
		  foreach my $line1 (split(/\n/,expand_hostgroup({dbh=>$dbh, line=>$line}))) {
		  	foreach my $line2 (split(/\n/,expand_portgroup({dbh=>$dbh, line=>$line1}))) {
		  		my ($snet, $dnet, $proto, $dport, $policy) = split(/[\s]+/, $line2);
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
		  		if ( $dport !~ /^0$/ ) {
		  			if ( $proto =~ /^icmp$/ ) {
		  				$outline .= " --icmp-type $dport";
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
  foreach $sql (split(/;/,$cfg->find('database/create'))) {
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

my $dbh = DBI->connect($cfg->find('database/dbd/@connectorstring'), { RaiseError => 1, AutoCommit => 1 });
if ($fw_privclients) {
	firewall_create_db($dbh);
}

if ($expand_hostgroups || $fw_privclients) {
  opendir(my $dh, $cfg->find('config/@path')."/groups") || die "can't opendir ".$cfg->find('config/@path')."/groups: $!\n";
  my @files = grep { /^hostgroup-/ && -f $cfg->find('config/@path')."/groups/$_" } readdir($dh);
  closedir $dh;
  my $path = $cfg->find('config/@path');
  foreach my $file (@files) {
  	my $name = $file;
  	$name =~ s/^hostgroup-//;
		parse_hostgroup({path=>$path, name=>$name, dbh=>$dbh});
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
		parse_portgroup({path=>$path, name=>$name, dbh=>$dbh});
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
	opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
	my @policies = grep { /^policy-routing-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
  foreach my $policydir (@policies) {
		-s $cfg->find('config/@path')."/$policydir/key" || next;
		my $policy = $policydir;
		$policy =~ s/^policy-routing-//;
		if ( -e $cfg->find('config/@path')."/$policydir/key" ) {
			open(my $cf, "<", $cfg->find('config/@path')."/$policydir/key") or die "cannot open < ".$cfg->find('config/@path')."/$policydir/key".": $!";
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

if ($fw_privclients) {
  opendir($dh, $cfg->find('config/@path')) || die "can't opendir ".$cfg->find('config/@path').": $!\n";
  @interfaces = grep { /^interface-/ && -d $cfg->find('config/@path')."/$_/" } readdir($dh);
	closedir $dh;

	print "Setting up IPSEC Spoof Protection\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/network-ipsec" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
	   open(my $cf, "<", $cfg->find('config/@path')."/$interfacedir/network-ipsec") or die "cannot open < ".$cfg->find('config/@path')."/$interfacedir/network-ipsec".": $!";
		foreach my $line (<$cf>) {
			chomp($line);
			$line =~ s/[ \t]*#.*//;
			$line =~ m/^[ \t]*$/ && next;
			print $FILEfilter "-A INPUT -s $line -i $iface -j in-$iface\n";
			print $FILEfilter "-A OUTPUT -d $line -o $iface -j out-$iface\n";
			print $FILEfilter "-A FORWARD -s $line -i $iface -j fwd-$iface\n";
			print $FILEfilter "-A INPUT -s $line -i $iface -j dns-in-$iface\n";
			print $FILEfilter "-A OUTPUT -d $line -o $iface -j dns-out-$iface\n";
			print $FILEfilter "-A FORWARD -s $line -i $iface -j dns-fwd-$iface\n";
			print $FILEmangle "-A PREROUTING -p esp -j MARK --set-mark 8000/0000\n";
			print $FILEmangle "-A PREROUTING -p ah -j MARK --set-mark 8000/0000\n";
				print $FILEmangle "-A in-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j $TARGETLOG\n";
				print $FILEmangle "-A fwd-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j $TARGETLOG\n";
				print $FILEmangle "-A in-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j DROP\n";
				print $FILEmangle "-A fwd-$iface -s $line -i $iface -m mark ! --mark 8000/8000 -j DROP\n";
		}
		close($cf);
		print $FILEnat "-A PREROUTING -i $iface -j pre-$iface\n";
		print $FILEnat "-A POSTROUTING -o $iface -j post-$iface\n";
	}

	print "Setting up Chains\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/network" || next;
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		if ( $iface =~ /^lo$/ ) {
      print $FILEfilter "-A OUTPUT -j in-$iface\n";
      print $FILEnat "-A OUTPUT -j pre-$iface\n";
      print $FILEnat "-A POSTROUTING -o $iface -j post-$iface\n";
      print $FILEfilter "-A OUTPUT -j dns-in-$iface\n";
      print $FILEnat "-A OUTPUT -j dns-pre-$iface\n";
      print $FILEnat "-A POSTROUTING -o $iface -j dns-post-$iface\n";
		} else {
			if ( -e $cfg->find('config/@path')."/$interfacedir/network" ) {
				open(my $cf, "<", $cfg->find('config/@path')."/$interfacedir/network") or die "cannot open < ".$cfg->find('config/@path')."/$interfacedir/network".": $!";
				foreach my $line (<$cf>) {
					chomp($line);
					$line =~ s/[ \t]*#.*//;
					$line =~ m/^[ \t]*$/ && next;
	        print $FILEfilter "-A INPUT -s $line -i $iface -j in-$iface\n";
	        print $FILEfilter "-A OUTPUT -d $line -o $iface -j out-$iface\n";
	        print $FILEfilter "-A FORWARD -s $line -i $iface -j fwd-$iface\n";
	        print $FILEfilter "-A INPUT -s $line -i $iface -j dns-in-$iface\n";
	        print $FILEfilter "-A OUTPUT -d $line -o $iface -j dns-out-$iface\n";
	        print $FILEfilter "-A FORWARD -s $line -i $iface -j dns-fwd-$iface\n";
				}
				close($cf);
			} else {
	      print STDERR "WARNING: Interface $iface has no network file\n";
			}
	    print $FILEnat "-A PREROUTING -i $iface -j pre-$iface\n";
	    print $FILEnat "-A POSTROUTING -o $iface -j post-$iface\n";
	    print $FILEnat "-A PREROUTING -i $iface -j dns-pre-$iface\n";
	    print $FILEnat "-A POSTROUTING -o $iface -j dns-post-$iface\n";
		}
	}
	print "Loopback Interface is fine\n";
	print $FILEfilter "-A OUTPUT	-j ACCEPT -o lo\n";
	print $FILEfilter "-A INPUT		-j ACCEPT -i lo\n";
	if ( -x $cfg->find('config/@path')."/script-pre" ) {
		print "Hook: script-pre\n";
		system($cfg->find('config/@path')."/script-pre");
	}
	print "Avoiding NAT\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/nonat" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/nonat");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_nonat($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/nonat",$commentchain);
	}
	print "Adding DNAT\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/dnat" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/dnat");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_dnat($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/dnat", $commentchain);
	}
	print "Adding SNAT\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/snat" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/snat");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_snat($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/snat", $commentchain);
	}
	print "Adding MASQUERADE\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/masquerade" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/masquerade");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_masquerade($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/masquerade", $commentchain);
	}
	print "Rejecting extra Clients\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/reject" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/reject");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_rejectclients($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/reject", $commentchain);
	}
	print "Adding priviledged Clients\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/privclients" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/privclients");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_privclients($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/privclients", $commentchain);
	}
	print "Adding Policy Routing\n";
	foreach my $interfacedir (@interfaces) {
		-s $cfg->find('config/@path')."/$interfacedir/policy-routing" || next;
		$commentchain=firewall_comment_add_key($dbh,"$interfacedir/policy-routing");
		my $iface = $interfacedir;
		$iface =~ s/^interface-//;
		foreach my $line (values(@{$comment{$iface}})) {
			print "  ".$line;
		}
		fw_policyrouting($dbh, $iface, $cfg->find('config/@path')."/$interfacedir/policy-routing", $commentchain);
	}
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
