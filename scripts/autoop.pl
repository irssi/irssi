# /AUTOOP <*|#channel> [<nickmasks>]
# use friends.pl if you need more features

use Irssi;
use strict;
use vars qw($VERSION %IRSSI);

$VERSION = "1.10";
%IRSSI = (
    authors     => 'Timo Sirainen & Jostein Kjønigsen',
    name        => 'autoop',
    description => 'Simple auto-op script',
    license     => 'Public Domain',
    changed	=> 'Fri Nov 24 12:55 GMT+1 2014'
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
			$channel->command("/op $nick");
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

sub load_autoops {
    my($file) = Irssi::get_irssi_dir."/autoop";
    my($count) = 0;
    local(*CONF);
    
    %opnicks = ();
    open(CONF, "<", "$file") or return;
    while (my $line = <CONF>) {
	if ($line !=~ /^\s*$/) {
	    cmd_autoop($line);
	    $count++;
	}
    }
    close(CONF);
    
    Irssi::print("Loaded $count channels from $file");
}

# --------[ save_autoops ]------------------------------------------------

sub save_autoops {
    my($auto) = @_;
    my($file) = Irssi::get_irssi_dir."/autoop";
    my($count) = 0;
    my($channel) = "";
    local(*CONF);
    
    return if $auto;
    
    open(CONF, ">", "$file");
    foreach $channel (keys %opnicks) {
	my $masks = $opnicks{$channel};
	print CONF "$channel\t$masks\n";
	$count++;
    }
    close(CONF);
    
    Irssi::print("Saved $count channels to $file")
	unless $auto;
}


# --------[ sig_setup_reread ]------------------------------------------

# main setup is reread, so let us do it too
sub sig_setup_reread {
    load_autoops;
}

# --------[ sig_setup_save ]--------------------------------------------

# main config is saved, and so we should save too
sub sig_setup_save {
    my($mainconf,$auto) = @_;
    save_autoops($auto);
}

# persistance

Irssi::signal_add('setup saved', 'sig_setup_save');
Irssi::signal_add('setup reread', 'sig_setup_reread');

# ensure we load persisted values on start
load_autoops;
