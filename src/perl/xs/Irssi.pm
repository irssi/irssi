#
# Perl interface to irssi functions.
#

package Irssi;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = "0.10";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw(channel_find_any);
@EXPORT_OK = qw();
bootstrap Irssi $VERSION;

1;

