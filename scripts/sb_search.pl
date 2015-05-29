# sb_search.pl - search in your scrollback, scroll to a match
# Do /HELP SCROLLBACK for help

# Copyright (C) 2008  Wouter Coekaerts <wouter@coekaerts.be>, Emanuele Giaquinta <exg@irssi.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

use strict;
use Irssi;
use Irssi::TextUI;
use vars qw($VERSION %IRSSI);

$VERSION = '1.1';
%IRSSI = (
	authors     => 'Wouter Coekaerts, Emanuele Giaquinta',
	contact     => 'wouter@coekaerts.be, exg@irssi.org',
	name        => 'sb_search',
	description => 'search in your scrollback, scroll to a match',
	license     => 'GPLv2 or later',
	url         => 'http://wouter.coekaerts.be/irssi/',
	changed     => '$LastChangedDate$',
);

sub cmd_help {
	my ($args, $server, $witem) = @_;
	if ($args =~ /^scrollback( search)? *$/i) {
		Irssi::print ( <<SCRIPTHELP_EOF

SCROLLBACK SEARCH [-level <level>] [-regexp] [-case] [-word] [-forward] [-all] [<pattern>]

    SEARCH:     Search for text in the scrollback buffer.

    -regexp:    The given text pattern is a regular expression.
    -case:      Performs a case-sensitive matching.
    -word:      The text must match full words.
    -forward:   Search forwards (default is backwards).
    -all:       Search in all windows.

    Without arguments, the last search is repeated.
SCRIPTHELP_EOF
			,MSGLEVEL_CLIENTCRAP);
	}
}

my $regex;
my $all;
my $level;

sub cmd_sb_search {
	my ($args, $server, $witem) = @_;
	
	### handle options
	
	my ($options, $pattern) = Irssi::command_parse_options('scrollback search', $args);

	my $forward = defined(delete $options->{forward});

	if (!%$options && !$pattern) {
		return if !$regex && !defined $level;
	} else {
		$all = defined($options->{all});
		$level = MSGLEVEL_ALL;
		undef $regex;
	}

	if (defined($options->{level})) {
		$level = $options->{level};
		$level =~ y/,/ /;
		$level = Irssi::combine_level(0, $level);
	}
	
	if ($pattern) {
		my $flags = defined($options->{case}) ? '' : '(?i)';
		my $b = defined($options->{word}) ? '\b' : '';
		if (defined($options->{regexp})) {
			local $@;
			eval {
				$regex = qr/$flags$b$pattern$b/;
			};
			if ($@) {
				my ($err) = $@ =~ /^(.*)/;
				$err =~ s/\sat .* line \d+\.$//;
				print CLIENTERROR $err;
				return;
			}
		} else {
			$regex = qr/$flags$b\Q$pattern\E$b/;
		}
	}
	

	### determine window(s) to search in
	
	my $current_win = ref $witem ? $witem->window() : Irssi::active_win();

	my @windows;
	if ($all) {
		# cycle backward or forwards over all windows starting from current
		# for example, searching backward through 5 windows, with window 3 active: search order is 3,2,1,5,4
		# if we're searching forward: 3,4,5,1,2
		my $order = $forward ? 1 : -1;
		@windows = sort {$order * ($a->{refnum} cmp $b->{refnum})} Irssi::windows();
		my @before_windows = grep {($_->{refnum} cmp $current_win->{refnum}) == $order} @windows;
		my @after_windows = grep {($_->{refnum} cmp $current_win->{refnum}) == -$order} @windows;
		@windows = ($current_win, @before_windows, @after_windows);
	} else {
		@windows = ($current_win);
	}
	
	### do the search
	
	foreach my $win (@windows) {
		my $view = $win->view;
		
		## determine line to start from
		my $line;
		if ($all && $win != $current_win) {
			if ($forward) { # first line
				$line = $view->get_lines;
			} else { # last line
				$line = $view->{startline};
				while ($line->next) {
					$line = $line->next
				}
			}
		} else { # line after or before first visible line
			$line = $forward ? $view->{startline}->next : $view->{startline}->prev;
		}
		
		## loop over the lines
		while (defined $line) {
			my $line_level = $line->{info}{level};
			if ($line_level & $level && $line->get_text(0) =~ $regex) {
				$view->scroll_line($line);
				if ($all) {
					Irssi::command('window goto ' . $win->{refnum});
				}
				return;
			}
			$line = $forward ? $line->next : $line->prev;
		}
	}
}

Irssi::command_bind('scrollback search', \&cmd_sb_search);
Irssi::command_bind_last('help', \&cmd_help);
Irssi::command_set_options('scrollback search', '-level regexp case word forward all');
