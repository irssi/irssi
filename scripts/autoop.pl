# /AUTOOP <*|#channel> [<nickmasks>]
# use friends.pl if you need more features

use Irssi;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.00";
%IRSSI = (
    authors     => 'Timo Sirainen',
    name        => 'autoop',
    description => 'Simple auto-op script',
    license     => 'Public Domain',
    changed	=> 'Sun Mar 10 23:18 EET 2002'
);

my (%opnicks, %temp_opped);

sub cmd_autoop {
	my ($data) = @_;
	my ($channel, $masks) = split(" ", $data, 2);

	if ($channel eq "") {
		if (!%opnicks) {
			Irssi::print("Usage: /AUTOOP <*|#channel> [<nickmasks>]");
			Irssi::print("No-one's being auto-opped currently.");
			return;
		}

		Irssi::print("Currently auto-opping in channels:");
		foreach $channel (keys %opnicks) {
			$masks = $opnicks{$channel};

			if ($channel eq "*") {
				Irssi::print("All channels: $masks");
			} else {
				Irssi::print("$channel: $masks");
			}
		}
		return;
	}

	if ($masks eq "") {
		$masks = "<no-one>";
		delete $opnicks{$channel};
	} else {
		$opnicks{$channel} = $masks;
	}
	if ($channel eq "*") {
		Irssi::print("Now auto-opping in all channels: $masks");
	} else {
		Irssi::print("$channel: Now auto-opping: $masks");
	}
}

sub autoop {
	my ($channel, $masks, @nicks) = @_;
	my ($server, $nickrec);

	$server = $channel->{server};
	foreach $nickrec (@nicks) {
		my $nick = $nickrec->{nick};
		my $host = $nickrec->{host};

                if (!$temp_opped{$nick} &&
		    $server->masks_match($masks, $nick, $host)) {
			$channel->command("op $nick");
			$temp_opped{$nick} = 1;
		}
	}
}

sub event_massjoin {
	my ($channel, $nicks_list) = @_;
	my @nicks = @{$nicks_list};

	return if (!$channel->{chanop});

	undef %temp_opped;

	# channel specific
	my $masks = $opnicks{$channel->{name}};
	autoop($channel, $masks, @nicks) if ($masks);

	# for all channels
	$masks = $opnicks{"*"};
	autoop($channel, $masks, @nicks) if ($masks);
}

Irssi::command_bind('autoop', 'cmd_autoop');
Irssi::signal_add_last('massjoin', 'event_massjoin');
