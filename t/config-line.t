use strict;
use warnings;
use Test::More;
use lib 'lib';

use LiHAS::Firewall::ConfigLine qw(expand_iface_placeholder);

is(
	expand_iface_placeholder(
		'hostgroup-@IFACE@-clients hostgroup-service tcp 443', 'eth0.10'
	),
	'hostgroup-eth0.10-clients hostgroup-service tcp 443',
	'interface placeholder is expanded in a rule',
);

is(
	expand_iface_placeholder('include include/privclients-@IFACE@', 'eth1'),
	'include include/privclients-eth1',
	'interface placeholder is expanded in an include path',
);

is(
	expand_iface_placeholder('hostgroup-static 192.0.2.0/24 tcp 443', 'eth0'),
	'hostgroup-static 192.0.2.0/24 tcp 443',
	'existing lines remain unchanged',
);

my $error = eval { expand_iface_placeholder('hostgroup-@IFACE@', 'bad iface'); 1 };
ok(!$error, 'unsafe interface name is rejected when placeholder is used');
like($@, qr/invalid interface name/, 'invalid interface error is explicit');

done_testing();
