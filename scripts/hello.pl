# "Hello, world!" script :) /hello <nick> sends "Hello, world!" to <nick>

use Irssi;
use Irssi::Irc;

sub cmd_hello {
	my ($data, $server, $channel) = @_;

	$server->command("/msg $data Hello, world!");
	return 1;
}

Irssi::command_bind('hello', '', 'cmd_hello');
