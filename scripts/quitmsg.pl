# If quit message isn't given, quit with a random message
# read from ~/.irssi/irssi.quit

use Irssi;
use Irssi::Irc;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.00";
%IRSSI = (
    authors     => 'Timo Sirainen',
    name        => 'quitmsg',
    description => 'Random quit messages',
    license     => 'Public Domain',
    changed	=> 'Sun Mar 10 23:18 EET 2002'
);

my $quitfile = glob "~/.irssi/irssi.quit";

sub cmd_quit {
	my ($data, $server, $channel) = @_;
	return if ($data ne "");

	open (f, $quitfile) || return;
	my $lines = 0; while(<f>) { $lines++; };

	my $line = int(rand($lines))+1;

	my $quitmsg;
	seek(f, 0, 0); $. = 0;
	while(<f>) {
		next if ($. != $line);

		chomp;
		$quitmsg = $_;
		last;
	}
	close(f);

	foreach my $server (Irssi::servers) {
		$server->command("disconnect ".$server->{tag}." $quitmsg");
	}
}

Irssi::command_bind('quit', 'cmd_quit');
