#
# Perl interface to irssi functions.
#

package Irssi;

use strict;
use Carp;
use vars qw($VERSION $in_irssi @ISA @EXPORT @EXPORT_OK);

# TIEHANDLE methods

sub TIEHANDLE {
  my ($class, $level, $object, $target) = @_;
  return bless [ $level, $object, $target ], $class;
}

sub WRITE {
  croak "Cannot syswrite() to an Irssi handle"
}

sub PRINT {
  my ($self, @list) = @_;
  if (defined $self->[1]) {
    if (defined $self->[2]) {
      $self->[1]->print($self->[2], join('', @list), $self->[0]);
    } else {
      $self->[1]->print(join('', @list), $self->[0]);
    }
  } else {
    Irssi::print(join('', @list), $self->[0]);
  }
}

sub PRINTF {
  my ($self, $format, @list) = @_;
  if (defined $self->[1]) {
    if (defined $self->[2]) {
      $self->[1]->print($self->[2], sprintf($format, @list), $self->[0]);
    } else {
      $self->[1]->print(sprintf($format, @list), $self->[0]);
    }
  } else {
    Irssi::print(sprintf($format, @list), $self->[0]);
  }
}

sub READ {
  croak "Cannot [sys]read() from an Irssi handle"
}

sub READLINE {
  croak "Cannot readline() from an Irssi handle"
}

sub GETC {
  croak "Cannot getc() from an Irssi handle"
}

sub CLOSE {}
sub UNTIE {}
sub DESTROY {}

# End of TIEHANDLE methods

# Handle creators

sub create_window_handle {
  my ($object, $level) = @_;
  $object = eval 'active_win'          unless defined $object;
  $level  = eval 'MSGLEVEL_CLIENTCRAP' unless defined $level;
  croak 'Usage: create_window_handle([$window[, $level]])'
    if ref $object !~ /::Window$/i;
  no strict 'refs';
  my $symref = 'Irssi::Handles::' . $object . '/' . $level;
  my $fh = \*{$symref};
  tie *{$symref}, __PACKAGE__, $level, $object;
  return $fh;
}

sub create_server_handle {
  my ($object, $target, $level) = @_;
  croak 'Usage: create_server_handle($server, $target[, $level])'
    if not defined $object
    or not defined $target
    or ref $object !~ /::Server$/i;
  $level = eval 'MSGLEVEL_CLIENTCRAP' unless defined $level;
  no strict 'refs';
  my $symref = 'Irssi::Handles::' . $object . '/' . $target . '/' . $level;
  my $fh = \*{$symref};
  tie *{$symref}, __PACKAGE__, $level, $object, $target;
  return $fh;
}

# Object interface for create_server_handle

sub Irssi::Server::create_handle {
  goto &Irssi::create_server_handle;
}

# Normal Irssi.pm stuff

sub VERSION {
  my $version = $_[1];
  die "This script requires irssi version $version or later"
    if ($version > version());
}

sub EXPORT_ALL () {
  my %exports = map { $_ => undef } @EXPORT, @EXPORT_OK;
  no strict 'refs';
  for (keys %Irssi::) {
    if (/^MSGLEVEL_/) {
      (my $short = $_) =~ s///;
      next if exists $exports{"*$short"};
      tie *{ $short }, __PACKAGE__, &$_();
      push @EXPORT, "*$short";
    } else {
      next if exists $exports{$_};
      push @EXPORT_OK, $_ if /[a-z]/ && defined *{$_}{CODE};
    }
  }

  tie *DEFAULT, __PACKAGE__, MSGLEVEL_CLIENTCRAP();
  select DEFAULT;
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
