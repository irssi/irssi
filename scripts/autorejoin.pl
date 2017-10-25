# automatically rejoin to channel after kicked
# delayed rejoin: Lam 28.10.2001 (lam@lac.pl)

# /SET autorejoin_channels #channel1 #channel2 ...
# /SET autorejoin_delay 5

# NOTE: I personally don't like this feature, in most channels I'm in it
# will just result as ban. You've probably misunderstood the idea of /KICK
# if you kick/get kicked all the time "just for fun" ...

use Irssi;
use Irssi::Irc;
use strict;
use vars qw($VERSION %IRSSI);
$VERSION = "1.1.0";
%IRSSI = (
	authors => "Timo 'cras' Sirainen, Leszek Matok",
	contact => "lam\@lac.pl",
	name => "autorejoin",
	description => "Automatically rejoin to channel after being kicked, after a (short) user-defined delay",
	license => "GPLv2",
	changed => "10.3.2002 14:00"
);

sub rejoin {
	my ( $data ) = @_;
	my ( $servtag, $channel, $pass ) = @{$data};

	my $server = Irssi::server_find_tag( $servtag );
	$server->send_raw( "JOIN $channel $pass" ) if ( $server );
}

sub event_rejoin_kick {
	my ( $server, $data ) = @_;
	my ( $channel, $nick ) = split( / +/, $data );

	return if ( $server->{ nick } ne $nick );

	# check if channel has password
	my $chanrec = $server->channel_find( $channel );
	my $password = $chanrec->{ key } if ( $chanrec );
	my $rejoinchan = $chanrec->{ name } if ( $chanrec );
	my $servtag = $server->{ tag };

	# check if we want to autorejoin this channel
	my $chans = Irssi::settings_get_str( 'autorejoin_channels' );

	if ( $chans ) {
		my $found = 0;
		foreach my $chan ( split( /[ ,]/, $chans ) ) {
			if ( lc( $chan ) eq lc( $channel ) ) {
				$found = 1;
				last;
			}
		}
		return unless $found;
	}

	my @args = ($servtag, $rejoinchan, $password);
	my $delay = Irssi::settings_get_int( "autorejoin_delay" );

	if ($delay) {
		Irssi::print "Rejoining $rejoinchan in $delay seconds.";
		Irssi::timeout_add_once( $delay * 1000, "rejoin", \@args );
	} else {
		rejoin( \@args );
	}
}

Irssi::settings_add_int('misc', 'autorejoin_delay', 5);
Irssi::settings_add_str('misc', 'autorejoin_channels', '');
Irssi::signal_add( 'event kick', 'event_rejoin_kick' );
