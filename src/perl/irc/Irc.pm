#
# Perl interface to irssi functions.
#

package Irssi::Irc;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.20";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();
@EXPORT_OK = qw();

bootstrap Irssi::Irc $VERSION;

@Irssi::Irc::Chatnet::ISA = qw(Irssi::Chatnet);
@Irssi::Irc::Server::ISA = qw(Irssi::Server);
@Irssi::Irc::ServerConnect::ISA = qw(Irssi::ServerConnect);
@Irssi::Irc::ServerSetup::ISA = qw(Irssi::ServerSetup);
@Irssi::Irc::Channel::ISA = qw(Irssi::Channel);
@Irssi::Irc::Query::ISA = qw(Irssi::Query);

1;

