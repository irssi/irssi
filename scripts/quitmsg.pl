# Quit with a random quit message read from ~/.irssi/irssi.quit

use Irssi;
use Irssi::Irc;

$quitfile = "$ENV{HOME}/.irssi/irssi.quit";

sub cmd_quit {
	my ($data, $server, $channel) = @_;

	open (f, $quitfile) || return;
	$lines = 0; while(<f>) { $lines++; };

	$line = int(rand($lines))+1;

	seek(f, 0, 0); $. = 0;
	while(<f>) {
		next if ($. != $line);

		chomp;
		$quitmsg = $_;
		last;
	}
	close(f);

	@servers = Irssi::servers;
	foreach $server (@servers) {
		$server->command("/disconnect ".$server->{tag}." $quitmsg");
	}
}

Irssi::command_bind('quit', '', 'cmd_quit');
