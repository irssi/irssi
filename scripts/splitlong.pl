# /set splitlong_max_length
#   specifies the maximum length of a msg, automatically chosen when set to "0"
###
use strict;
use vars qw($VERSION %IRSSI);

#don't know which version exactly, probably even works with 0.7.98.4
use Irssi 20011001;

$VERSION = "0.17";
%IRSSI = (
	authors     => "Bjoern \'fuchs\' Krombholz",
	contact     => "bjkro\@gmx.de",
	name        => "splitlong",
	licence     => "Public Domain",
	description => "Split overlong PRIVMSGs to msgs with length allowed by ircd",
	changed     => "Wed Mar  8 03:03:10 CET 2002",
	changes     => "fixed some strange bug, depends on new switches to msg command (-nick|-channel)"
);

sub sig_command_msg {
	my ($cmd, $server, $winitem, $TEST) = @_;
	my ($type, $target, $data) = $cmd =~ /^(\S*)\s(\S*)\s(.*)/;
	my $maxlength = Irssi::settings_get_int('splitlong_max_length');

	if ($maxlength == 0) {
		# 497 = 510 - length(":" . "!" . " PRIVMSG " . " :");
		$maxlength = 497 - length($server->{nick} . $server->{userhost} . $target);
	}
	my $maxlength2 = $maxlength - length("... ");

	if (length($data) > ($maxlength)) {
		my @spltarr;

		while (length($data) > ($maxlength2)) {
			my $pos = rindex($data, " ", $maxlength2);
			push @spltarr, substr($data, 0, ($pos < ($maxlength/10 + 4)) ? $maxlength2  : $pos) . " ...";

			$data = "... " . substr($data, ($pos < ($maxlength/10 + 4)) ? $maxlength2 : $pos+1);
		}

		push @spltarr, $data;
		foreach (@spltarr) {
			Irssi::signal_emit("command msg", "$type $target $_", $server, $winitem);
		}
		Irssi::signal_stop();
	}
}

Irssi::settings_add_int('misc', 'splitlong_max_length', 0);

Irssi::command_bind('msg', 'sig_command_msg');
