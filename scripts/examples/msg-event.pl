# Example how to react on specific messages:

# !reverse <text> sends back the text reversed.

use Irssi;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.00";
%IRSSI = (
    authors     => 'Timo Sirainen',
    name        => 'msg-event',
    description => 'Event example',
    license     => 'Public Domain'
);

sub event_privmsg {
	# $server = server record where the message came
	# $data = the raw data received from server, with PRIVMSGs it is:
	#         "target :text" where target is either your nick or #channel
	# $nick = the nick who sent the message
	# $host = host of the nick who sent the message
	my ($server, $data, $nick, $host) = @_;

	# split data to target/text
	my ($target, $text) = $data =~ /^(\S*)\s:(.*)/;

	# skip lines not beginning with !reverse
	return if ($text !~ /!reverse (.*)/);
	$text = $1;

	if (!$server->ischannel($target)) {
		# private message, $target contains our nick, so we'll need
		# to change it to $nick
		$target = $nick;
	}

	$server->command("notice $target reversed $text = ".reverse($text));
}

Irssi::signal_add('event privmsg', 'event_privmsg');
