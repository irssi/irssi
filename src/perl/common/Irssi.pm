#
# Perl interface to irssi functions.
#

package Irssi;

use strict;
use vars qw($VERSION $in_irssi @ISA @EXPORT @EXPORT_OK);

sub VERSION {
  my $version = $_[1];
  die "This script requires irssi version $version or later"
    if ($version > version());
}

sub EXPORT_ALL () {
  no strict 'refs';
  @EXPORT_OK = grep { /[a-z]/ && defined *{$_}{CODE} } keys %Irssi::;
}

sub in_irssi {
  return $in_irssi;
}

$VERSION = "0.9";

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw(INPUT_READ INPUT_WRITE
	MSGLEVEL_CRAP MSGLEVEL_MSGS MSGLEVEL_PUBLIC MSGLEVEL_NOTICES
	MSGLEVEL_SNOTES MSGLEVEL_CTCPS MSGLEVEL_ACTIONS MSGLEVEL_JOINS
	MSGLEVEL_PARTS MSGLEVEL_QUITS MSGLEVEL_KICKS MSGLEVEL_MODES
	MSGLEVEL_TOPICS MSGLEVEL_WALLOPS MSGLEVEL_INVITES MSGLEVEL_NICKS
	MSGLEVEL_DCC MSGLEVEL_DCCMSGS MSGLEVEL_CLIENTNOTICE MSGLEVEL_CLIENTCRAP
	MSGLEVEL_CLIENTERROR MSGLEVEL_HILIGHT MSGLEVEL_ALL MSGLEVEL_NOHILIGHT
	MSGLEVEL_NO_ACT MSGLEVEL_NEVER MSGLEVEL_LASTLOG
);
@EXPORT_OK = qw();

my $static = 0;

eval {
  $static = Irssi::Core::is_static();
};
$in_irssi = $@ ? 0 : 1;

if (!in_irssi()) {
  print "Warning: This script should be run inside irssi\n";
} else {
  bootstrap Irssi $VERSION if (!$static);

  @Irssi::Channel::ISA = qw(Irssi::Windowitem);
  @Irssi::Query::ISA = qw(Irssi::Windowitem);

  Irssi::init();

  Irssi::EXPORT_ALL();
}

1;

