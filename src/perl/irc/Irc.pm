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

Irssi::Irc::init();

1;

