package LiHAS::Firewall::DNS;
use warnings;
use strict;
use POE;
use XML::Application::Config;

sub DEBUG () { 1 }; # display more information
sub TIMER_DELAY { 10 };
sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions

my $named = POE::Component::Client::DNS->spawn(
  Alias => "named"
);

#------------------------------------------------------------------------------
# This session uses the ping component to resolve things.
sub dns_query {
  my ($kernel, $type, $name) = @_[KERNEL, ARG0, ARG1];
  print "DNSquery: $type, $name\n";
  my $response = $named->resolve(
    event   => "dns_response",
    host    => $name,
    context => { },
  );
  if ($response) {
    $kernel->yield(dns_response => $response);
  }
}

sub dns_response {
  my ($kernel,$heap,$response) = @_[KERNEL, HEAP, ARG0];
  my @answers = $response->{response}->answer();
  foreach my $answer (@answers) {
    print(
      "$response->{host} = ",
      $answer->type(), " ",
      $answer->rdatastr(), "\n"
    );
  }
}

1;
