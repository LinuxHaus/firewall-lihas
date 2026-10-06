package LiHAS::Firewall::ConfigLine;
use warnings;
use strict;
use Exporter qw(import);

our @EXPORT_OK = qw(expand_iface_placeholder);

sub expand_iface_placeholder {
	my ($line, $iface) = @_;
	return $line if not defined($line) or index($line, '@IFACE@') < 0;
	die "cannot expand \@IFACE\@: invalid interface name\n"
		if not defined($iface) or $iface !~ /\A[a-zA-Z0-9_.-]+\z/;
	$line =~ s/\@IFACE\@/$iface/g;
	return $line;
}

1;
