# /RN - display real name of nick

use Irssi;
use Irssi::Irc;
use strict;

sub cmd_realname {
	my ($data, $server, $channel) = @_;

	$server->send_raw("WHOIS :$data");

	# ignore all whois replies except "No such nick" or the 
	# first line of the WHOIS reply
	$server->redirect_event($data, 2,
			  "event 318", "event empty", -1,
			  "event 402", "event 402", -1,
			  "event 401", "event 401", 1,
			  "event 311", "redir whois", 1,
			  "event 301", "event empty", 1,
			  "event 312", "event empty", 1,
			  "event 313", "event empty", 1,
			  "event 317", "event empty", 1,
			  "event 319", "event empty", 1);
}

sub event_rn_whois {
	my ($num, $nick, $user, $host, $empty, $realname) = split(/ +/, $_[1], 6);
	$realname =~ s/^://;

	Irssi::print("%_$nick%_ is $realname");
}

Irssi::command_bind('rn', 'cmd_realname');
Irssi::signal_add('redir whois', 'event_rn_whois');
