#
# Perl interface to irssi functions.
#

package Irssi;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.20";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();
@EXPORT_OK = qw();

bootstrap Irssi $VERSION;

@Irssi::Ircnet::ISA = qw(Irssi::Chatnet);
@Irssi::IrcServer::ISA = qw(Irssi::Server);
@Irssi::IrcServerConnect::ISA = qw(Irssi::ServerConnect);
@Irssi::IrcServerSetup::ISA = qw(Irssi::ServerSetup);

@Irssi::Channel::ISA = qw(Irssi::WindowItem);
@Irssi::Query::ISA = qw(Irssi::WindowItem);
@Irssi::IrcChannel::ISA = qw(Irssi::Channel);
@Irssi::IrcQuery::ISA = qw(Irssi::Query);

1;

