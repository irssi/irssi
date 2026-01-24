#
# Perl interface to irssi functions.
#

package Irssi::Irc::Dcc;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.9";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();
@EXPORT_OK = qw();

bootstrap Irssi::Irc::Dcc $VERSION if (!Irssi::Core::is_static());

Irssi::Irc::Dcc::init();

Irssi::EXPORT_ALL();

1;

