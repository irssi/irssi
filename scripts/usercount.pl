use Irssi 20020101.0250 ();
$VERSION = "1.16";
%IRSSI = (
    authors     => 'David Leadbeater, Timo Sirainen, Georg Lukas',
    contact     => 'dgl@dgl.cx, tss@iki.fi, georg@boerde.de',
    name        => 'usercount',
    description => 'Adds a usercount for a channel as a statusbar item',
    license     => 'GNU GPLv2 or later',
    url         => 'http://irssi.dgl.yi.org/',
);

# Once you have loaded this script run the following command:
# /statusbar window add usercount
# You can also add -alignment left|right option

# /set usercount_show_zero on or off to show users when 0 users of that type
# /set usercount_show_ircops (default off)
# /set usercount_show_halfops (default on)

# you can customize the look of this item from theme file:
#  sb_usercount = "{sb %_$0%_ nicks ($1-)}";
#  sb_uc_ircops = "%_*%_$*";
#  sb_uc_ops = "%_@%_$*";
#  sb_uc_halfops = "%_%%%_$*";
#  sb_uc_voices = "%_+%_$*";
#  sb_uc_normal = "$*";
#  sb_uc_space = " ";


use strict;
use Irssi::TextUI;

my ($ircops, $ops, $halfops, $voices, $normal, $total);
my ($timeout_tag, $recalc);

# Called to make the status bar item
sub usercount {
  my ($item, $get_size_only) = @_;
  my $wi = !Irssi::active_win() ? undef : Irssi::active_win()->{active};

  if(!ref $wi || $wi->{type} ne "CHANNEL") { # only works on channels
    return unless ref $item;
    $item->{min_size} = $item->{max_size} = 0;
    return;
  }

  if ($recalc) {
    $recalc = 0;
    calc_users($wi);
  }

  my $theme = Irssi::current_theme();
  my $format = $theme->format_expand("{sb_usercount}");
  if ($format) {
    # use theme-specific look
    my $ircopstr = $theme->format_expand("{sb_uc_ircops $ircops}",
          Irssi::EXPAND_FLAG_IGNORE_EMPTY);
    my $opstr = $theme->format_expand("{sb_uc_ops $ops}",
          Irssi::EXPAND_FLAG_IGNORE_EMPTY);
    my $halfopstr = $theme->format_expand("{sb_uc_halfops $halfops}",
          Irssi::EXPAND_FLAG_IGNORE_EMPTY);
    my $voicestr = $theme->format_expand("{sb_uc_voices $voices}", 
          Irssi::EXPAND_FLAG_IGNORE_EMPTY);
    my $normalstr = $theme->format_expand("{sb_uc_normal $normal}",
          Irssi::EXPAND_FLAG_IGNORE_EMPTY);
	my $space = $theme->format_expand('{sb_uc_space}',
         Irssi::EXPAND_FLAG_IGNORE_EMPTY);
	$space = " " unless $space;

    my $str = "";
    $str .= $ircopstr.$space if defined $ircops;
    $str .= $opstr.$space  if defined $ops;
    $str .= $halfopstr.$space if defined $halfops;
    $str .= $voicestr.$space if defined $voices;
    $str .= $normalstr.$space if defined $normal;
    $str =~ s/\Q$space\E$//;

    $format = $theme->format_expand("{sb_usercount $total $str}",
				    Irssi::EXPAND_FLAG_IGNORE_REPLACES);
  } else {
    # use the default look
    $format = "{sb \%_$total\%_ nicks \%c(\%n";
    $format .= '*'.$ircops.' ' if (defined $ircops);
    $format .= '@'.$ops.' ' if (defined $ops);
    $format .= '%%'.$halfops.' ' if (defined $halfops);
    $format .= "+$voices " if (defined $voices);
    $format .= "$normal " if (defined $normal);
    $format =~ s/ $//;
    $format .= "\%c)}";
  }

  $item->default_handler($get_size_only, $format, undef, 1);
}

sub calc_users() {
  my $channel = shift;
  my $server = $channel->{server};

  $ircops = $ops = $halfops = $voices = $normal = 0;
  for ($channel->nicks()) {
    if ($_->{serverop}) {
      $ircops++;
	}

    if ($_->{op}) {
      $ops++;
	} elsif ($_->{halfop}) {
	   $halfops++;
    } elsif ($_->{voice}) {
      $voices++;
    } else {
      $normal++;
    }
  }

  $total = $ops+$halfops+$voices+$normal;
  if (!Irssi::settings_get_bool('usercount_show_zero')) {
    $ircops = undef if ($ircops == 0);
    $ops = undef if ($ops == 0);
    $halfops = undef if ($halfops == 0);
    $voices = undef if ($voices == 0);
    $normal = undef if ($normal == 0);
  }
  $halfops = undef unless Irssi::settings_get_bool('usercount_show_halfops');
  $ircops = undef unless Irssi::settings_get_bool('usercount_show_ircops');
}

sub refresh {
   if ($timeout_tag > 0) {
      Irssi::timeout_remove($timeout_tag);
      $timeout_tag = 0;
   }
   Irssi::statusbar_items_redraw('usercount');
}

sub refresh_check {
   my $channel = shift;
   my $wi = ref Irssi::active_win() ? Irssi::active_win()->{active} : 0;

   return unless ref $wi && ref $channel;
   return if $wi->{name} ne $channel->{name};
   return if $wi->{server}->{tag} ne $channel->{server}->{tag};

   # don't refresh immediately, or we'll end up refreshing 
   # a lot around netsplits
   $recalc = 1;
   Irssi::timeout_remove($timeout_tag) if ($timeout_tag > 0);
   $timeout_tag = Irssi::timeout_add(500, 'refresh', undef);
}

sub refresh_recalc {
  $recalc = 1;
  refresh();
}

$recalc = 1;
$timeout_tag = 0;

Irssi::settings_add_bool('usercount', 'usercount_show_zero', 1);
Irssi::settings_add_bool('usercount', 'usercount_show_ircops', 0);
Irssi::settings_add_bool('usercount', 'usercount_show_halfops', 1);

Irssi::statusbar_item_register('usercount', undef, 'usercount');
Irssi::statusbars_recreate_items();

Irssi::signal_add_last('nicklist new', 'refresh_check');
Irssi::signal_add_last('nicklist remove', 'refresh_check');
Irssi::signal_add_last('nick mode changed', 'refresh_check');
Irssi::signal_add_last('setup changed', 'refresh_recalc');
Irssi::signal_add_last('window changed', 'refresh_recalc');
Irssi::signal_add_last('window item changed', 'refresh_recalc');

