# automatically rejoin to channel after kicked

# NOTE: I personally don't like this feature, in most channels I'm in it
# will just result as ban. You've probably misunderstood the idea of /KICK
# if you kick/get kicked all the time "just for fun" ...

use Irssi;
use Irssi::Irc;

sub event_rejoin_kick {
	my ($server, $data) = @_;
	my ($channel, $nick) = split(/ +/, $data);

	return if ($server->{nick} ne $nick);

	# check if channel has password
	$chanrec = $server->channel_find($channel);
	$password = $chanrec->{key} if ($chanrec);

	# We have to use send_raw() because the channel record still
	# exists and irssi won't even try to join to it with command()
	$server->send_raw("JOIN $channel $password");
}

Irssi::signal_add('event kick', 'event_rejoin_kick');
