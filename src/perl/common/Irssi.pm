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
@EXPORT = qw(INPUT_READ INPUT_WRITE);
@EXPORT_OK = qw();

bootstrap Irssi $VERSION;

@Irssi::Channel::ISA = qw(Irssi::Windowitem);
@Irssi::Query::ISA = qw(Irssi::Windowitem);

1;

