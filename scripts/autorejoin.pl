# automatically rejoin to channel after kicked

# /SET autorejoin_channels #channel1 #channel2 ...

# NOTE: I personally don't like this feature, in most channels I'm in it
# will just result as ban. You've probably misunderstood the idea of /KICK
# if you kick/get kicked all the time "just for fun" ...

use strict;
use Irssi::Irc;

sub channel_rejoin {
  my ($server, $channel) = @_;

  # check if channel has password
  my $chanrec = $server->channel_find($channel);
  my $password = $chanrec->{key} if ($chanrec);

  # We have to use send_raw() because the channel record still
  # exists and irssi won't even try to join to it with command()
  $server->send_raw("JOIN $channel $password");
}

sub event_rejoin_kick {
  my ($server, $data) = @_;
  my ($channel, $nick) = split(/ +/, $data);

  return if ($server->{nick} ne $nick);

  # check if we want to autorejoin this channel
  my @chans = split(/ ,/, Irssi::settings_get_str('autorejoin_channels'));
  foreach my $chan (@chans) {
    if (lc($chan) eq lc($channel)) {
      channel_rejoin($server, $channel);
      last;
    }
  }
}

Irssi::settings_add_str('misc', 'autorejoin_channels', '');
Irssi::signal_add('event kick', 'event_rejoin_kick');
