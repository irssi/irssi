#
# Perl interface to irssi functions.
#

package Irssi::TextUI;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.8";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();
@EXPORT_OK = qw();

bootstrap Irssi::TextUI $VERSION;

Irssi::TextUI::init();

1;

