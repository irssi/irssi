# listen PRIVMSGs - send a notice to yourself when your nick is meantioned

use Irssi;
use Irssi::Irc;

sub event_privmsg {
	my ($data, $server, $nick, $address) = @_;
	my ($target, $text) = $data =~ /^(\S*)\s:(.*)/;

	return if (!$server->ischannel($target));

	$mynick = $server->values()->{'nick'};
	return if ($text !~ /\b$mynick\b/);

	$server->command("/notice $mynick In channel $target, $nick!$address said: $text");
}

Irssi::signal_add("event privmsg", "event_privmsg");
