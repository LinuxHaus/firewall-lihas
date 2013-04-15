package LiHAS::Firewall::DNS;
use warnings;
use strict;
use POE;
use XML::Application::Config;

sub DEBUG () { 1 }; # display more information
sub TIMER_DELAY { 10 };
sub PING_TIMEOUT () { 5 }; # seconds between pings
sub PING_COUNT () { 1 }; # ping repetitions

sub new ($) {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self = {};

  $self->{cfg} = $_[0];

  my $named = POE::Component::Client::DNS->spawn(
    Alias => "named"
  );

  bless ($self,$class);
  bless ($named,$class);
  return $self;
} 

#------------------------------------------------------------------------------
# This session uses the ping component to resolve things.
sub dns_query {
  my $self = shift;
  my ($kernel) = $_[KERNEL];

  my $response = $self->named->resolve(
    event   => "response",
    host    => "localhost",
    context => { },
  );
  if ($response) {
    $kernel->yield(response => $response);
  }
}

sub dns_response {
  my $self = shift;
  my $response = $_[ARG0];
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
