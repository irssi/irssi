# If quit message isn't given, quit with a random message
# read from ~/.irssi/irssi.quit

use Irssi;
use Irssi::Irc;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.01";
%IRSSI = (
    authors     => 'Timo Sirainen',
    name        => 'quitmsg',
    description => 'Random quit messages',
    license     => 'Public Domain',
    changed	=> 'Mon Jul 22 20:00 EET 2020'
);

my $quitfile = Irssi::get_irssi_dir() . "/irssi.quit";

sub cmd_quit {
	my ($data, $server, $channel) = @_;
	return if ($data ne "");
	
	open (my $fh, "<", $quitfile) || return;
	my @lines = <$fh>;

	my $quitmsg = $lines[int(rand(@lines))];
	chomp($quitmsg);
	close($fh);

	foreach my $server (Irssi::servers) {
		$server->command("/disconnect ".$server->{tag}." $quitmsg");
	}
}

Irssi::command_bind('quit', 'cmd_quit');
