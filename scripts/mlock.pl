# /MLOCK <channel> <mode>
#
# Locks the channel mode to <mode>, if someone else tries to change the mode
# Irssi will automatically change it back. +k and +l are a bit special since
# they require the parameter. If you omit the parameter, like setting the
# mode to "+ntlk", Irssi will allow all +k and +l (or -lk) mode changes.

use Irssi;
use Irssi::Irc;

sub cmd_mlock {
	my ($data, $server) = @_;
	my ($channel, $mode) = split(/ /, $data, 2);

	$keep_channels{$channel} = $mode;
	mlock_check_mode($server, $channel);
        return 1;
}

sub mlock_check_mode {
        my ($server, $channame) = @_;

	$channel = $server->channel_find($channame);
	return if (!channel || !$channel->{chanop});

        $keep_mode = $keep_channels{$channame};
	return if (!$keep_mode);

	# old channel mode
	$oldmode = $channel->{mode};
        $oldmode =~ s/^([^ ]*).*/\1/;
	$oldkey = $channel->{key};
	$oldlimit = $channel->{limit};

	# get the new channel key/limit
	@newmodes = split(/ /, $keep_mode); $keep_mode = $newmodes[0];
	if ($keep_mode =~ /k/) {
		if ($keep_mode =~ /k.*l/) {
                        $newkey = $newmodes[1];
                        $limit = $newmodes[2];
		} elsif ($keep_mode =~ /l.*k/) {
			$limit = $newmodes[1];
                        $newkey = $newmodes[2];
		} else {
                        $newkey = $newmodes[1];
		}
	} elsif ($keep_mode =~ /l/) {
		$limit = $newmodes[1];
	}

	# check the differences
	undef %allmodes;
	$keep_mode =~ s/^\+//;
	for ($n = 0; $n < length($keep_mode); $n++) {
		$modechar = substr($keep_mode, $n, 1);
		$allmodes{$modechar} = '+';
	}

	for ($n = 0; $n < length($oldmode); $n++) {
		$modechar = substr($oldmode, $n, 1);

		if ($allmodes{$modechar} eq '+') {
			next if (($modechar eq "k" && $newkey ne $oldkey) ||
				 ($modechar eq "l" && $limit != $oldlimit));
			delete $allmodes{$modechar};
		} else {
			$allmodes{$modechar} = '-';
		}
	}

	# create the mode change string
        $modecmd = ""; $extracmd = "";
	foreach $mode (keys %allmodes) {
		Irssi::print("key = '$mode':".$allmodes{$mode});
		if ($mode eq "k") {
			if ($allmodes{$mode} eq '+') {
				next if ($newkey eq "");
				if ($oldkey ne "") {
					# we need to get rid of old key too
					$modecmd .= "-k";
					$extracmd .= " $oldkey";
				}
				$extracmd .= " $newkey";
			} else {
				$extracmd .= " $oldkey";
			}
		}
		if ($mode eq "l" && $allmodes{$mode} eq '+') {
			next if ($limit <= 0);
                        $extracmd .= " $limit";
		}
		$modecmd .= $allmodes{$mode}.$mode;
	}

	if ($modecmd ne "") {
		$channel->{server}->command("/mode $channame $modecmd$extracmd");
	}
}

sub mlock_mode_changed {
	my ($server, $data) = @_;
	my ($channel, $mode) = split(/ /, $data, 2);

	mlock_check_mode($server, $channel);
}

sub mlock_synced {
	my $channel = $_[0];

	mlock_check_mode($channel->{server}, $channel->{name});
}

Irssi::command_bind('mlock', '', 'cmd_mlock');
Irssi::signal_add_last("event mode", "mlock_mode_changed");
Irssi::signal_add("channel synced", "mlock_synced");
