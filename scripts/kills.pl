# Display kills with more understandable messages.
# for irssi 0.7.98 by Timo Sirainen

# There's one kind of nick collision this script doesn't handle - if the
# collision is detected by the server you're connected to, it won't use
# kill as quit reason, but "Nick collision(new)" or "..(old)". This is pretty
# easy to understand already, happens hardly ever(?) and it can be faked
# so I thought better not change it to kill message.

# There's a pretty good explanation of (ircnet) ircd's server kills in
# http://www.irc.org/tech_docs/ircnet/kills.html

use Irssi;
use vars qw($VERSION %IRSSI);

$VERSION = "1.00";
%IRSSI = (
    authors	=> 'Timo Sirainen',
    name	=> 'kills',
    description	=> 'Displays kills with more understandable messages',
    license	=> 'Public Domain',
    changed	=> 'Sun Mar 10 23:18 EET 2002'
);

Irssi::theme_register([
  'kill_public', '{channick $0} {chanhost $1} killed by {nick $2}$3 {reason $4}'
]);

sub msg_quit {
  my ($server, $nick, $addr, $data) = @_;

  my $localkill;
  if ($data =~ /^Killed \(([^ ]*) \((.*)\)\)$/) {
    # remote kill
    $localkill = 0;
  } elsif ($data =~ /^Local Kill by ([^ ]*) \((.*)\)/) {
    # local kill
    $localkill = 1;
  } else {
    return;
  }

  my $killer = $1;
  my $killmsg = $2;
  my $msg = "\002Nick collision\002: ";

  my @printargs = ();
  if ($killmsg =~ /([^ ]*) != (.*)/) {
    # 1 != 2
    my $server1 = $1, $server2 = $2;

    $server1 =~ s/([^\[]*)\[([^\]]*)\]/\1/;
    $msg .= "$2 != $server2";
  } elsif ($killmsg =~ /([^ ]*) <- (.*)/) {
    # 1 <- 2
    my $server1 = $1, $server2 = $2;

    if ($server1 =~ /^\(/) {
      # (addr1)server1 <- (add2)server2
      $server1 =~ s/^\(([^\)]*)\)//;
      my $nick1 = $1;
      $server2 =~ s/^\(([^\)]*)\)//;
      my $nick2 = $1;

      $msg .= "server $server1";
      $msg .= " (nick from $nick1)" if $nick1;
      $msg .= " <- ";
      $msg .= "\002$server2\002";
      $msg .= " (nick from \002$nick2\002)" if $nick2;
    } elsif ($server1 =~ /\)$/ || $server2 =~ /\)$/) {
      # server1(nick) <- server2
      # server1 <- server2(nick)
      $server1 =~ s/\(([^\)]*)\)$//;
      my $oldnick = $1;
      $server2 =~ s/\(([^\)]*)\)$//;
      $oldnick = $1 if $1;
      $msg = "\002Nick change collision\002: $server1 <- \002$server2\002 (old nick \002$oldnick\002)";
    } else {
      # server1 <- server2
      $msg = "\002Nick/server collision\002: $server1 <- \002$server2\002";
    }
  } else {
    # something else, just show it as-is
    $msg = $killmsg;
  }

  @list = $server->nicks_get_same($nick);
  while (@list) {
    $channel = $list[0];
    shift @list;
    # skip nick record
    shift @list;

    $channel->printformat(MSGLEVEL_QUITS, 'kill_public',
                          $nick, $addr, $killer,
			  $localkill ? " (local)" : "", $msg);
  }

  Irssi::signal_stop();
}

Irssi::signal_add('message quit', 'msg_quit');
