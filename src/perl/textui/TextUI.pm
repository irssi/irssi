#
# Perl interface to irssi functions.
#

package Irssi::TextUI;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.9";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw();
@EXPORT_OK = qw();

bootstrap Irssi::TextUI $VERSION if (!Irssi::Core::is_static());

Irssi::TextUI::init();

Irssi::EXPORT_ALL();

1;

