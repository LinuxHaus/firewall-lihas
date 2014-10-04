package LiHAS::Firewall::IPSEC;
use warnings;
use strict;
use POE;
use XML::Application::Config;
use Log::Log4perl qw(:easy);

sub ipsec_get_dnsnames () {
	my $logger = $1;
	my $ipsecsecretssource = $2;
	my $ipsecsecretshosts = $3;
	if ( -r $ipsecsecretssource ) {
		if ( ! open($fdhosts, $ipsecsecretshosts) ) {
			$logger->fatal("cannot open $ipsecsecretshosts: $!");
			$logger->fatal("IPSEC DNS-names won't work");
		} else {
			if ( ! open($fdsecrets, $ipsecsecretssource) ) {
				
			}
		}
	}
}
# vim: ts=2 sw=2 sts=2 sr noet
1;
