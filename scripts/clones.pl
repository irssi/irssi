# /CLONES - Display clones in the active channel
# Modified by Roi Dayan. dejavo@punkass.com

use strict;

sub cmd_clones {
  my ($data, $server, $channel) = @_;
  my $min_show_count = ($data =~ /^[0-9]+$/) ? $data : 2;

  if (!$channel || $channel->{type} ne "CHANNEL") {
    Irssi::print("No active channel in window");
    return;
  }

  my %hostnames = {};
  my %hostnicks = {};
  my @hosttmp = {};
  foreach my $nick ($channel->nicks()) {
    my @hosttmp = split(/\@/,$nick->{host});
    $hostnames{$hosttmp[1]}++;
    $hostnicks{$hosttmp[1]} = $hostnicks{$hosttmp[1]}.$hostnames{$hosttmp[1]}.". ".$nick->{nick}."!".$nick->{host}."\n";
    $hostnicks{$hosttmp[1]} =~ s/^,//;
#    $hostnicks{$hosttmp[1]} =~ s/\n$//;
  }
  
  foreach my $nick (keys %hostnicks) {
    $hostnicks{$nick} =~ s/\n$//;
  }

  my $count = 0;
  foreach my $host (keys %hostnames) {
    my $clones = $hostnames{$host};
    if ($clones >= $min_show_count) {
      $channel->print("Clones:") if ($count == 0);
      $channel->print("$host: $clones $hostnicks{$host}");
      $count++;
    }
  }

  $channel->print("No clones in channel") if ($count == 0);
}

Irssi::command_bind('clones', 'cmd_clones');
