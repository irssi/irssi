# /CLONES - Display clones in the active channel

use Irssi;
use strict;

sub cmd_clones {
  my ($data, $server, $channel) = @_;

  if (!$channel || $channel->{type} ne "CHANNEL") {
    Irssi::print("No active channel in window");
    return;
  }

  my %hostnames = {};
  foreach my $nick ($channel->nicks()) {
    $hostnames{$nick->{host}}++;
  }

  my $count = 0;
  foreach my $host (keys %hostnames) {
    my $clones = $hostnames{$host};
    if ($clones >= 2) {
      $channel->print("Clones:") if ($count == 0);
      $channel->print("$host: $clones");
      $count++;
    }
  }

  $channel->print("No clones in channel") if ($count == 0);
}

Irssi::command_bind('clones', 'cmd_clones');
