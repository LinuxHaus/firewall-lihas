package LiHAS::Firewall::DNS;

use warnings;
use strict;
use POE;
use XML::Application::Config;

our $VERSION = '$Id$';

sub DEBUG () { 1 }; # display more information

sub TIMER_DELAY { 10 };
sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions

my $cfg = new XML::Application::Config("LiHAS-Firewall","config.xml");
my $testcount = $cfg->find('tests/@count');
our @addresses;

my $i;

DEBUG and print "active: ".$cfg->find('dns/@active')."\n";
if ($cfg->find('tests/@active')!=0) {
  for ($i=1; $i<=$testcount; $i++) {
    $addresses[$i-1] = $cfg->find('tests/test['.$i.']/@host');
  };
}

# Create a pinger component.
POE::Component::Client::Ping->spawn(
  Alias => 'pinger', # This is the name it'll be known by.
  OneReply => 1,     # stop after 1st reply.
  Timeout => PING_TIMEOUT, # This is how long it waits for echo replies.
);

#------------------------------------------------------------------------------
# This session uses the ping component to resolve things.

sub ping_client_start {
  my ($kernel, $session, $heap) = @_[KERNEL, SESSION, HEAP];

  # Set up recording.
  $heap->{requests} = 0;
  $heap->{answers} = 0;
  $heap->{dones} = 0;
  $heap->{ping_counts} = { };

  # Start pinging.
  foreach my $address (@addresses) {
    $heap->{ping_counts}->{$address} = 0;
    $kernel->call( $session, client_send_ping => $address );
  }
}

sub client_send_ping {
  my ($kernel, $session, $heap, $address) = @_[KERNEL, SESSION, HEAP, ARG0];

  DEBUG and warn( $session->ID, ": pinging $address...\n" );

  $heap->{requests}++;
  $heap->{ping_counts}->{$address}++;
  $kernel->post(
    'pinger', # Post the request to the 'pinger'.
    'ping', # Ask it to 'ping' an address.
    'client_got_pong', # Have it post an answer to my 'pong' state.
    $address, # This is the address we want it to ping.
    PING_TIMEOUT # This is the optional time to wait.
  );
}

sub client_got_pong {
  my ($kernel, $session, $heap, $request_packet, $response_packet) =
    @_[KERNEL, SESSION, HEAP, ARG0, ARG1];

  my ($request_address, $request_timeout, $request_time) = @{$request_packet};
  my (
    $response_address, $roundtrip_time, $reply_time, $reply_ttl
  ) = @{$response_packet};

  if (defined $response_address) {
    DEBUG and warn(
      sprintf(
        "%d: ping to %-15.15s at %10d. " .
        "pong from %-15.15s in %6.3f s (ttl %3d)\n",
        $session->ID,
        $request_address, $request_time,
        $response_address, $roundtrip_time, $reply_ttl,
      )
    );

    $heap->{answers}++ if $roundtrip_time <= $request_timeout;
    $heap->{bad_ttl}++ if (
      $reply_ttl !~ /^\d+$/ or
      $reply_ttl < 0 or
      $reply_ttl > 255
    );
  }
  else {
    DEBUG and warn( $session->ID, ": time's up for $request_address...\n" );
  }

  $kernel->yield(client_send_ping => $request_address) if (
    $heap->{ping_counts}->{$request_address} < PING_COUNT
  );

  $heap->{dones}++;
}

sub client_stop {
  my ($session, $heap) = @_[SESSION, HEAP];
  DEBUG and warn( $session->ID, ": pinger client session stopped...\n" );

  warn("REQUESTS: ".$heap->{requests}."\nDONES: ".$heap->{dones}."\nANSWERS: ".$heap->{answers});

  ok(
    (
      $heap->{requests} == $heap->{dones}
      && $heap->{answers}
      && !$heap->{bad_ttl}
    ),
    "pinger client session got responses"
  );
}

sub timer_ping {
      my ($kernel, $session) = @_[KERNEL, ARG0];
        $_[KERNEL]->post($_[SESSION], "ping_client_start", @_ );
	  $kernel->delay('timer_ping', TIMER_DELAY);
}

1
