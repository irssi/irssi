use Irssi;
use strict;
use v5.14;
use List::Util qw(min max);
use Hash::Util qw(lock_keys);

our $VERSION = '2.1'; # a42b713aaa38823
our %IRSSI = (
    authors	=> 'Nei',
    contact	=> 'Nei @ anti@conference.jabber.teamidiot.de',
    url		=> "http://anti.teamidiot.de/",
    name	=> 'nm2',
    description => 'right aligned nicks depending on longest nick',
    license	=> 'GPL v2',
);

# based on bc-bd's original nm.pl
#
# use a ** nickcolor_expando ** script for nick colors!
#
# why is there no right_mode? you can do that in your theme!

# Options
# =======
# /set neat_dynamic <ON|OFF>
# * whether the width should be dynamically chosen on each incoming
#   message
#
# /set neat_shrink <ON|OFF>
# * whether shrinking of the width is allowed, or only growing
#
# /set neat_staircase_shrink <ON|OFF>
# * whether shrinking should be done one character at a time
#
# The following styles decide if the nick is left/right aligned and
# where the colour/mode goes, they're a bit complex...
# put the desired indicator(s) between the appropriate "," and the
# default format of the public messages or actions will be rewritten
# appropriately.
# This can be used to align the nick left or right, before or after
# the nick brackets and before or between the nickmode (by using the
# pad on the correct place). To change the mode from left of the nick
# to right of the nick, you need to modify the abstracts in your theme
# however.
# By placing the colour at the end, you can even colour the message
# text in the nick colour, however it might be broken if there are
# other colour codes used inside the message or by scripts.
#
# /format neat_style      , , , , , , , ,
#                        î î î î î î î î î
# p: pad                 | | | | | | | | `before message
# c: colour              | | | | | | | `-after msgchannel
# t: truncate indicator  | | | | | | `-before msgchannel
#                        | | | | | `-after nick
#                        | | | | `-before nick
#                        | | | `-after mode
#                        | | `-before mode
#                        | `-before msgnick
#                        `-none
#
# /format neat_action_style  , , , ,
#                           î î î î î
# p: pad                    | | | | `-before message
# c: colour                 | | | `-after nick
# t: truncate indicator     | | `-before nick
#                           | `-before action
#                           `-none
#
# /format neat_pad_char <char>
# * the character(s) used for padding
#
# /format neat_truncate_char
# * the format or character to indicate that nick was truncated
#
# /format neat_notruncate_char
# * the format or character to indicate that nick NOT was truncated
#
# /format neat_customize_modes @@ | ++ |  ?
# * a |-separated mapping of mode prefixes and their rendition, can be
#   used to replace or colourise them
#
# /set neat_color_hinick <ON|OFF>
# * whether to use colours in hilighted messages
#
# /set neat_color_menick <ON|OFF>
# * whether to use colours in hilight_nick_matches
#
# /set neat_truncate_nick <ON|OFF>
# * whether to truncate overlong nicks
#
# /set neat_custom_modes <ON|OFF>
# * whether to enable the use of neat_customize_modes format
#
# /set neat_maxlength <number>
# * number : (maximum) length to use for nick padding
#
# /set neat_melength <number>
# * number : width to substract from maxlength for /me padding
#
# /set neat_history <number>
# * number : number of formatted lines to remember for dynamic mode
#

my @action_protos = qw(irc silc xmpp);
my (%histories, %S, @style, @astyle, %format_ok, %cmmap);

my $align_expando = '';
my $trunc_expando = '';
my $cumode_expando = '';

my $format_re = qr/ %(?=[}%{])
		    | %[04261537kbgcrmywKBGCRMYWU9_8I:|FnN>#pP[]
		    | %[Zz][[:xdigit:]]{6}
		    | %[Xx](?i:0[a-f]|[1-6][0-9a-z]|7[a-x]) /x;

sub update_expando {
    my ($mode, $server, $target, $nick, $space) = @_;
    my $t_add;
    if (exists $Irssi::Script::{'realnames::'}
	    && (my $code = 'Irssi::Script::realnames'->can('_get_nick_chan'))) {
	if (my $i = $code->($server, $target, $nick)) {
	    $nick = $i->{n}{realname}
		if length $i->{n}{realname};
	}
    }
    my $nl = length $nick;
    my $pad_len = max(0, $space - $nl);
    if ($S{truncate_nick}) {
	if (($mode >= 4 && $S{trunc_in_anick})
		|| ($mode < 4 && $S{trunc_in_nick})) {
	    $t_add = $S{tnolen};
	}
	if ($nl + $t_add > $space) {
	    $trunc_expando = format_expand($S{tyes_char});
	    $t_add = $S{tyeslen} if defined $t_add;
	}
	else {
	    $trunc_expando = format_expand($S{tno_char});
	}
	$pad_len = max(0, $pad_len - $t_add) if $t_add;
    }
    else {
	$trunc_expando = '';
    }
    if ($pad_len) {
	my @subs = split /($format_re)/, $S{pad_char} x $pad_len;
	$align_expando = '';
	my $clen = 0;
	while (@subs) {
	    my ($tx, $fmt) = splice @subs, 0, 2;
	    my $txlen = length $tx // 0;
	    $align_expando .= substr $tx, 0, ($pad_len - $clen) if defined $tx;
	    $clen += $txlen;
	    $align_expando .= $fmt if defined $fmt;
	    last if $clen >= $pad_len;
	}
	$align_expando = format_expand($align_expando.'%n');
    }
    else {
	$align_expando = '';
    }
    return $t_add;
}

sub prnt_clear_levels {
    my ($dest) = @_;
    clear_ref() if $dest->{level}
	& (MSGLEVEL_PUBLIC|MSGLEVEL_MSGS|MSGLEVEL_ACTIONS|MSGLEVEL_DCCMSGS|MSGLEVEL_NOTICES);
}

sub clear_ref {
    $trunc_expando = $align_expando = $cumode_expando = '';
}

sub expando_nickalign { $align_expando }
sub expando_nicktrunc { $trunc_expando }
sub expando_nickcumode { $cumode_expando }

Irssi::expando_create('nickalign', \&expando_nickalign, {
    'message public'	     => 'none',
    'message own_public'     => 'none',
    'message private'	     => 'none',
    'message own_private'    => 'none',
    (map { ("message $_ action"     => 'none',
	    "message $_ own_action" => 'none')
       } @action_protos),
   });
Irssi::expando_create('nicktrunc', \&expando_nicktrunc, {
    'message public'	     => 'none',
    'message own_public'     => 'none',
    'message private'	     => 'none',
    'message own_private'    => 'none',
    (map { ("message $_ action"     => 'none',
	    "message $_ own_action" => 'none')
       } @action_protos),
   });
Irssi::expando_create('nickcumode', \&expando_nickcumode, {
    'message public'	     => 'none',
    'message own_public'     => 'none',
    'message private'	     => 'none',
    'message own_private'    => 'none',
    (map { ("message $_ action"     => 'none',
	    "message $_ own_action" => 'none')
       } @action_protos),
   });

sub init_hist {
    my ($server, $target) = @_;
    if (my $ch = $server->channel_find($target)) {
	[ max map { length } map { $_->{nick} } $ch->nicks ]
    }
    else {
	[ max map { length } $server->{nick}, $target ]
    }
}

my %em = (
    p => '$nickalign',
    c => '$nickcolor',
    t => '$nicktrunc',
    m => '$nickcumode',
   );

my %formats = (
    own_action		   => [5, '{ownaction ',      '$0','}','$1' ],
    action_public	   => [4, '{pubaction ',      '$0','}','$1' ],
    action_private	   => [4, '{pvtaction ',      '$0','}','$2' ],
    action_private_query   => [4, '{pvtaction_query ','$0','}','$2' ],
    #                          * *                   * #  *   *

    own_msg_private_query  => [3, '{ownprivmsgnick ', ''  ,'{ownprivnick ','$2','}',''               ,'}','$1' ],
    msg_private_query	   => [2, '{privmsgnick '    ,''  ,''             ,'$0','' ,''               ,'}','$2' ],
    own_msg		   => [1, '{ownmsgnick '     ,'$2',' {ownnick '   ,'$0','}',''               ,'}','$1' ],
    own_msg_channel	   => [1, '{ownmsgnick '     ,'$3',' {ownnick '   ,'$0','}','{msgchannel $1}','}','$2' ],
    pubmsg_me		   => [0, '{pubmsgmenick '   ,'$2',' {menick '    ,'$0','}',''               ,'}','$1' ],
    pubmsg_me_channel	   => [0, '{pubmsgmenick '   ,'$3',' {menick '    ,'$0','}','{msgchannel $1}','}','$2' ],
    pubmsg_hilight	   => [0, '{pubmsghinick $0 ','$3',' '            ,'$1', '','',              ,'}','$2' ],
    pubmsg_hilight_channel => [0, '{pubmsghinick $0 ','$4',' '            ,'$1', '','{msgchannel $2}','}','$3' ],
    pubmsg		   => [0, '{pubmsgnick '     ,'$2',' {pubnick '   ,'$0','}',''               ,'}','$1' ],
    pubmsg_channel	   => [0, '{pubmsgnick '     ,'$3',' {pubnick '   ,'$0','}','{msgchannel $1}','}','$2' ],
    #                          * *                   *    *            * #  *   *                 *   *
   );

sub reformat_format {
    Irssi::signal_remove('command format', 'update_formats');
    Irssi::signal_remove('theme changed'  => 'update_formats');
    %format_ok = () unless @_;
    my ($mode, $server, $target, $nick, $size) = @_;
    for my $fmt (keys %formats) {
	next if defined $mode && $formats{$fmt}[0] != $mode;

	my @fs = @{ $formats{$fmt} };

	my $ls;
	if (defined $mode) {
	    $ls = $size;
	}
	else {
	    $ls = $fs[0] < 4 ? $S{max} : max(0, $S{max} - $S{melength});
	}
	next if exists $format_ok{$fmt} && $format_ok{$fmt} == $ls;

	if ($S{truncate_nick} && $ls) {
	    $fs[ $fs[0] < 4 ? 4 : 2 ] =~ s/\$/\$[.$ls]/;
	}
	if ($S{custom_modes} && $fs[0] < 4) {
	    $fs[2] =~ s/\$\K\d/nickcumode/;
	}
	my $s;
	local $em{c} = ''
	    if ($fs[1] =~ /menick/ && !$S{color_menick})
		|| ($fs[1] =~ /hinick/ && !$S{color_hinick});
	my $sr = $fs[0] >= 4 ? \@astyle : \@style;
	for my $i (1..$#fs) {
	    $s .= ($sr->[$i] =~ s/(.)/$em{$1}/gr) if defined $sr->[$i];
	    $s .= $fs[$i];
	}
	Irssi::command("^format $fmt $s");
	$format_ok{$fmt} = $ls;
    }
    Irssi::signal_add_last({
	'theme changed'  => 'update_formats',
	'command format' => 'update_formats',
    });
}

sub update_nm {
    my ($mode, $server, $target, $nick) = @_;
    my $tg = $server->{tag};
    if (my $ch = $server->channel_find($target)) {
	$target = $ch->{name};
	my $nickobj = $ch->nick_find($nick);
	if ($nickobj) {
	    $nick = $nickobj->{nick};
	    my $mode = substr $nickobj->{prefixes}.' ', 0, 1;
	    $cumode_expando = exists $cmmap{$mode} ? format_expand($cmmap{$mode}) : $mode;
	}
	else {
	    $cumode_expando = '';
	}
    }
    elsif (my $q = $server->query_find($target)) {
	$target = $q->{name};
    }

    my $longest;
    if ($S{dynamic}) {
	my $hist = $histories{"$tg/$target"} ||= init_hist($server, $target);
	my $last = $histories{"$tg/$target/last"} || 1;
	unshift @$hist, length $nick;
	if (@$hist > 2*$S{history}) {
	    splice @$hist, $S{history};
	}
	my @add;
	unless ($S{shrink}) {
	    push @add, $last;
	}
	if ($S{staircase}) {
	    push @add, $last - 1
	}
	$longest = $histories{"$tg/$target/last"} = max(@$hist, @add);

	if ($S{max} && ($S{max} < $longest || !$S{shrink})) {
	    $longest = $S{max};
	}
    }
    else {
	$longest = $S{max};
    }

    my $size = $mode < 4 ? $longest : max(0, $longest - $S{melength});
    my $t_add = update_expando($mode, $server, $target, $nick, $size);
    $size = max(0, $size - $t_add) if defined $t_add;
    if ($S{dynamic}) {
	reformat_format($mode, $server, $target, $nick, $size);
    }
}

sub sig_setup {
    my %old_S = %S;
    $S{history}	 = Irssi::settings_get_int('neat_history');
    $S{max}	 = Irssi::settings_get_int('neat_maxlength');
    $S{melength} = Irssi::settings_get_int('neat_melength');

    $S{dynamic}	    = Irssi::settings_get_bool('neat_dynamic');
    $S{shrink}	    = Irssi::settings_get_bool('neat_shrink');
    $S{staircase}   = Irssi::settings_get_bool('neat_staircase_shrink');

    $S{color_hinick}  = Irssi::settings_get_bool('neat_color_hinick');
    $S{color_menick}  = Irssi::settings_get_bool('neat_color_menick');
    $S{truncate_nick} = Irssi::settings_get_bool('neat_truncate_nick');
    $S{custom_modes}  = Irssi::settings_get_bool('neat_custom_modes');

    if (!defined $old_S{dynamic} || $old_S{dynamic} != $S{dynamic}) {
	%histories = ();
	reformat_format();
    }
    elsif ($old_S{max} != $S{max} || $old_S{melength} != $S{melength}
	       || $old_S{color_hinick} != $S{color_hinick} || $old_S{color_menick} != $S{color_menick}
		   || $old_S{truncate_nick} != $S{truncate_nick} || $old_S{custom_modes} != $S{custom_modes}) {
	reformat_format();
    }
}

sub update_formats {
    my $was_style = "@style";
    $S{style} = Irssi::current_theme->get_format(__PACKAGE__, 'neat_style');
    my $was_action_style = "@astyle";
    $S{action_style} = Irssi::current_theme->get_format(__PACKAGE__, 'neat_action_style');
    $S{pad_char} = Irssi::current_theme->get_format(__PACKAGE__, 'neat_pad_char');
    $S{tno_char} = Irssi::current_theme->get_format(__PACKAGE__, 'neat_notruncate_char');
    $S{tnolen} = length($S{tno_char} =~ s/$format_re//gr);
    $S{tyeslen} = length($S{tyes_char} =~ s/$format_re//gr);
    $S{tyes_char} = Irssi::current_theme->get_format(__PACKAGE__, 'neat_truncate_char');
    @style = map { y/pct//cd; $_ } split /,/, $S{style};
    @astyle = map { y/pctm//cd; $_ } split /,/, $S{action_style};
    $S{trunc_in_nick} = grep { /t/ } @style[2..min($#style, 6)];
    $S{trunc_in_anick} = grep { /t/ } @astyle[2..min($#astyle, 3)];
    my $custom_modes = Irssi::current_theme->get_format(__PACKAGE__, 'neat_custom_modes');
    %cmmap = map { (substr $_, 0, 1), (substr $_, 1) } $custom_modes =~ /(?:^\s?|\G\s?\|\s?)((?!\s\|)(?:[^\\|[:space:]]|\\.|\s(?!\||$))*)/sg;
    if ($was_style ne "@style" || $was_action_style ne "@astyle") {
	reformat_format();
    }
}

{
    my %format2control = (
	'F' => "\cDa", '_' => "\cDc", '|' => "\cDe", '#' => "\cDi", "n" => "\cDg", "N" => "\cDg",
	'U' => "\c_", '8' => "\cV", 'I' => "\cDf",
       );
    my %bg_base = (
	'0'   => '0', '4' => '1', '2' => '2', '6' => '3', '1' => '4', '5' => '5', '3' => '6', '7' => '7',
	'x08' => '8', 'x09' => '9', 'x0a' => ':', 'x0b' => ';', 'x0c' => '<', 'x0d' => '=', 'x0e' => '>', 'x0f' => '?',
       );
    my %fg_base = (
	'k' => '0', 'b' => '1', 'g' => '2', 'c' => '3', 'r' => '4', 'm' => '5', 'p' => '5', 'y' => '6', 'w' => '7',
	'K' => '8', 'B' => '9', 'G' => ':', 'C' => ';', 'R' => '<', 'M' => '=', 'P' => '=', 'Y' => '>', 'W' => '?',
       );
    my @ext_colour_off = (
	'.', '-', ',',
	'+', "'", '&',
       );
    sub format_expand {
	$_[0] =~ s{%(Z.{6}|z.{6}|X..|x..|.)}{
	    my $c = $1;
	    if (exists $format2control{$c}) {
		$format2control{$c}
	    }
	    elsif (exists $bg_base{$c}) {
		"\cD/$bg_base{$c}"
	    }
	    elsif (exists $fg_base{$c}) {
		"\cD$fg_base{$c}/"
	    }
	    elsif ($c =~ /^[{}%]$/) {
		$c
	    }
	    elsif ($c =~ /^(z|Z)([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2})$/) {
		my $bg = $1 eq 'z';
		my (@rgb) = map { hex $_ } $2, $3, $4;
		my $x = $bg ? 0x1 : 0;
		my $out = "\cD" . (chr -13 + ord '0');
		for (my $i = 0; $i < 3; ++$i) {
		    if ($rgb[$i] > 0x20) {
			$out .= chr $rgb[$i];
		    }
		    else {
			$x |= 0x10 << $i; $out .= chr 0x20 + $rgb[$i];
		    }
		}
		$out .= chr 0x20 + $x;
		$out
	    }
	    elsif ($c =~ /^(x)(?:0([[:xdigit:]])|([1-6])(?:([0-9])|([a-z]))|7([a-x]))$/i) {
		my $bg = $1 eq 'x';
		my $col = defined $2 ? hex $2
		    : defined $6 ? 232 + (ord lc $6) - (ord 'a')
			: 16 + 36 * ($3 - 1) + (defined $4 ? $4 : 10 + (ord lc $5) - (ord 'a'));
		if ($col < 0x10) {
		    my $chr = chr $col + ord '0';
		    "\cD" . ($bg ? "/$chr" : "$chr/")
		}
		else {
		    "\cD" . $ext_colour_off[($col - 0x10) / 0x50 + $bg * 3] . chr (($col - 0x10) % 0x50 - 1 + ord '0')
		}
	    }
	    else {
		"%$c"
	    }
        }ger;
    }
}

sub init {
    update_formats();
    sig_setup();
    lock_keys(%S);
    print "nm2 experimental version, please report issues. thanks!"
}

Irssi::settings_add_bool('misc', 'neat_dynamic', 1);
Irssi::settings_add_bool('misc', 'neat_shrink', 1);
Irssi::settings_add_bool('misc', 'neat_staircase_shrink', 0);

Irssi::settings_add_bool('misc', 'neat_color_hinick', 0);
Irssi::settings_add_bool('misc', 'neat_color_menick', 0);
Irssi::settings_add_bool('misc', 'neat_truncate_nick', 1);
Irssi::settings_add_bool('misc', 'neat_custom_modes', 0);

Irssi::settings_add_int('misc', 'neat_maxlength', 0);
Irssi::settings_add_int('misc', 'neat_melength', 2);
Irssi::settings_add_int('misc', 'neat_history', 50);

Irssi::signal_add('setup changed' => 'sig_setup');
Irssi::signal_add_last({
    'setup reread'   => 'sig_setup',
    'theme changed'  => 'update_formats',
    'command format' => 'update_formats',
   });

Irssi::theme_register([
    'neat_style'	   => ' , , p , , c , t , , , ',
    'neat_action_style'	   => ' , p , , t , ',
    'neat_pad_char'	   => '%K.',
    'neat_truncate_char'   => '%m+',
    'neat_notruncate_char' => '',
    'neat_custom_modes'    => '&%B&%n | @%g@%n | +%y+%n',
   ]);

Irssi::signal_add_first({
    'message public' => sub {
	my ($server, $msg, $nick, $address, $target) = @_;
	update_nm(0, $server, $target, $nick);
    },
    'message private' => sub {
	my ($server, $msg, $nick, $address) = @_;
	update_nm(2, $server, $nick, $nick);
    },
    (map { ("message $_ action" => sub {
	my ($server, $msg, $nick, $address, $target) = @_;
	update_nm(4, $server, $target, $nick);
    }) } qw(irc silc)),
    'message xmpp action' => sub {
	return unless @_;
	my ($server, $msg, $nick, $target) = @_;
	update_nm(4, $server, $target, $nick);
    },
   });

sub channel_nick {
    my ($server, $target) = @_;
    ($server->channel_find($target)||+{ownnick=>$server})->{ownnick}{nick}
}

Irssi::signal_add_first({
    'message own_public' => sub {
	my ($server, $msg, $target) = @_;
	update_nm(1, $server, $target, channel_nick($server, $target));
    },
    'message own_private' => sub {
	my ($server, $msg, $target) = @_;
	update_nm(3, $server, $target, $server->{nick});
    },
    (map { ("message $_ own_action" => sub {
	my ($server, $msg, $target) = @_;
	update_nm(5, $server, $target, $server->{nick});
    }) } qw(irc silc)),
    'message xmpp own_action' => sub {
	return unless @_;
	my ($server, $msg, $target) = @_;
	update_nm(5, $server, $target, channel_nick($server, $target));
    },
   });
Irssi::signal_add_last({
    'channel destroyed' => sub {
	my ($channel) = @_;
	delete $histories{ $channel->{server}{tag} . '/' . $channel->{name} };
	delete $histories{ $channel->{server}{tag} . '/' . $channel->{name} . '/last' };
    },
    'query destroyed' => sub {
	my ($query) = @_;
	delete $histories{ $query->{server}{tag} . '/' . $query->{name} };
	delete $histories{ $query->{server}{tag} . '/' . $query->{name} . '/last' };
    },
    'query nick changed' => sub {
	my ($query, $old_nick) = @_;
	delete $histories{ $query->{server}{tag} . '/' . $old_nick };
	delete $histories{ $query->{server}{tag} . '/' . $old_nick . '/last' };
    },
    'query server changed' => sub {
	my ($query, $old_server) = @_;
	delete $histories{ $old_server->{tag} . '/' . $query->{name} };
	delete $histories{ $old_server->{tag} . '/' . $query->{name} . '/last' };
    }
   });
Irssi::signal_add({
    'print text' => 'prnt_clear_levels',
});

init();

# Changelog
# =========
# 2.1 - support realnames script
#
# 2.0
# - fix crash if xmpp action signal is not registered (just ignore it)
# - do not grow either when using no-shrink with maxlength
# - hopefully fix alignment in xmpp muc
