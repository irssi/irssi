#
# Perl interface to irssi functions.
#

package Irssi::UI;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.20";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw(active_win active_server print command printformat);
@EXPORT_OK = qw();

bootstrap Irssi::UI $VERSION;

Irssi::UI::init();

1;

