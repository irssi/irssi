# "Hello, world!" script :) /hello <nick> sends "Hello, world!" to <nick>

use Irssi;
use strict;

sub cmd_hello {
	my ($data, $server, $channel) = @_;

	$server->command("/msg $data Hello, world!");
}

Irssi::command_bind('hello', 'cmd_hello');
