# automatically rejoin to channel after kicked

# NOTE: I personally don't like this feature, in most channels I'm in it
# will just result as ban. You've probably misunderstood the idea of /KICK
# if you kick/get kicked all the time "just for fun" ...

use Irssi;

sub event_rejoin_kick {
	my ($data, $server) = @_;
	my ($channel) = split(/ +/, $data);

	# check if channel has password
	$chanrec = $server->channel_find($channel);
	$password = $chanrec->values()->{'key'} if ($chanrec);

	$server->send_raw("JOIN $channel $password");
}

Irssi::signal_add('event kick', 'event_rejoin_kick');
