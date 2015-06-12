# automatically rejoin to channel after kick
# delayed rejoin: Lam 28.10.2001 (lam@lac.pl)

# NOTE: I personally don't like this feature, in most channels I'm in it
# will just result as ban. You've probably misunderstood the idea of /KICK
# if you kick/get kicked all the time "just for fun" ...

use Irssi;
use Irssi::Irc;
use strict;
use vars qw($VERSION %IRSSI);
$VERSION = "1.0.0";
%IRSSI = (
	authors => "Timo 'cras' Sirainen, Leszek Matok",
	contact => "lam\@lac.pl",
	name => "autorejoin",
	description => "Automatically rejoin to channel after being kick, after a (short) user-defined delay",
	license => "GPLv2",
	changed => "10.3.2002 14:00"
);


# How many seconds to wait before the rejoin?
# TODO: make this a /setting
my $delay = 5;

my @tags;
my $acttag = 0;

sub rejoin {
	my ( $data ) = @_;
	my ( $tag, $servtag, $channel, $pass ) = split( / +/, $data );

	my $server = Irssi::server_find_tag( $servtag );
	$server->send_raw( "JOIN $channel $pass" ) if ( $server );
	Irssi::timeout_remove( $tags[$tag] );
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

	Irssi::print "Rejoining $rejoinchan in $delay seconds.";
	$tags[$acttag] = Irssi::timeout_add( $delay * 1000, "rejoin", "$acttag $servtag $rejoinchan $password" );
	$acttag++;
	$acttag = 0 if ( $acttag > 60 );
}

Irssi::signal_add( 'event kick', 'event_rejoin_kick' );
