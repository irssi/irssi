# Example how to do redirections, we'll grab the output of /WHOIS:

# /RN - display real name of nick

use Irssi;
use Irssi::Irc;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.00";
%IRSSI = (
    authors     => 'Timo Sirainen',
    name        => 'redirect',
    description => 'Redirection example',
    license     => 'Public Domain'
);

sub cmd_realname {
	my ($data, $server, $channel) = @_;

	# ignore all whois replies except "No such nick" or the 
	# first line of the WHOIS reply
	$server->redirect_event('whois', 1, $data, -1, '', {
			  'event 402' => 'event 402',
			  'event 401' => 'event 401',
			  'event 311' => 'redir whois',
			  '' => 'event empty' });

	$server->send_raw("WHOIS :$data");
}

sub event_rn_whois {
	my ($num, $nick, $user, $host, $empty, $realname) = split(/ +/, $_[1], 6);
	$realname =~ s/^://;

	Irssi::print("%_$nick%_ is $realname");
}

Irssi::command_bind('rn', 'cmd_realname');
Irssi::signal_add('redir whois', 'event_rn_whois');
