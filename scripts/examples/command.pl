# Example how to create your own /commands:

# /HELLO <nick> - sends a "Hello, world!" to given nick.

use Irssi;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.00";
%IRSSI = (
    authors     => 'Timo Sirainen',
    name        => 'command',
    description => 'Command example',
    license     => 'Public Domain'
);

sub cmd_hello {
	my ($data, $server, $channel) = @_;

	$server->command("/msg $data Hello, world!");
}

Irssi::command_bind('hello', 'cmd_hello');
