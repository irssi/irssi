/*
 screen.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"

#include "screen.h"
#include "gui-readline.h"
#include "mainwindows.h"

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <signal.h>

#ifndef COLOR_PAIRS
#define COLOR_PAIRS 64
#endif

#define MIN_SCREEN_WIDTH 20

static int scrx, scry;
static int use_colors;
static int freeze_refresh;

#ifdef SIGWINCH

static void sig_winch(int p)
{
#ifdef TIOCGWINSZ
	struct winsize ws;
	int ychange, xchange;

	/* Get new window size */
	if (ioctl(0, TIOCGWINSZ, &ws) < 0)
		return;

	if (ws.ws_row == LINES && ws.ws_col == COLS) {
		/* Same size, abort. */
		return;
	}

	if (ws.ws_col < MIN_SCREEN_WIDTH)
		ws.ws_col = MIN_SCREEN_WIDTH;

	/* Resize curses terminal */
	ychange = ws.ws_row-LINES;
	xchange = ws.ws_col-COLS;
#ifdef HAVE_CURSES_RESIZETERM
	resizeterm(ws.ws_row, ws.ws_col);
#else
	deinit_screen();
	init_screen();
#endif

	mainwindows_resize(ychange, xchange != 0);
#endif
}
#endif

/* FIXME: SIGINT != ^C .. any better way to make this work? */
void sigint_handler(int p)
{
	ungetch(3);
	readline();
}

static void read_settings(void)
{
	const char *ignores;

	use_colors = settings_get_bool("colors");

	ignores = settings_get_str("ignore_signals");
	signal(SIGHUP, find_substr(ignores, "hup") ? SIG_IGN : SIG_DFL);
	signal(SIGQUIT, find_substr(ignores, "quit") ? SIG_IGN : SIG_DFL);
	signal(SIGTERM, find_substr(ignores, "term") ? SIG_IGN : SIG_DFL);
	signal(SIGPIPE, find_substr(ignores, "pipe") ? SIG_IGN : SIG_DFL);
	signal(SIGALRM, find_substr(ignores, "alrm") ? SIG_IGN : SIG_DFL);
	signal(SIGUSR1, find_substr(ignores, "usr1") ? SIG_IGN : SIG_DFL);
	signal(SIGUSR2, find_substr(ignores, "usr2") ? SIG_IGN : SIG_DFL);
	irssi_redraw();
}

/* Initialize screen, detect screen length */
int init_screen(void)
{
	char ansi_tab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	int num;

	if (!initscr()) return 0;

	if (COLS < MIN_SCREEN_WIDTH)
		COLS = MIN_SCREEN_WIDTH;

	signal(SIGINT, sigint_handler);
	cbreak(); noecho(); idlok(stdscr, 1);
#ifdef HAVE_CURSES_IDCOK
	idcok(stdscr, 1);
#endif
	intrflush(stdscr, FALSE); halfdelay(1); keypad(stdscr, 1);

	settings_add_bool("lookandfeel", "colors", TRUE);
	settings_add_str("misc", "ignore_signals", "");

	use_colors = settings_get_bool("colors") && has_colors();
	if (has_colors()) start_color();

#ifdef HAVE_NCURSES_USE_DEFAULT_COLORS
	/* this lets us to use the "default" background color for colors <= 7 so
	   background pixmaps etc. show up right */
	use_default_colors();

	for (num = 1; num < COLOR_PAIRS; num++)
		init_pair(num, ansi_tab[num & 7], num <= 7 ? -1 : ansi_tab[num >> 3]);

	init_pair(63, 0, -1); /* hm.. not THAT good idea, but probably more
	                         people want dark grey than white on white.. */
#else
	for (num = 1; num < COLOR_PAIRS; num++)
		init_pair(num, ansi_tab[num & 7], ansi_tab[num >> 3]);
	init_pair(63, 0, 0);
#endif

	scrx = scry = 0;
#ifdef SIGWINCH
	signal(SIGWINCH, sig_winch);
#endif

	freeze_refresh = 0;
	clear();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	return 1;
}

/* Deinitialize screen */
void deinit_screen(void)
{
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	endwin();
}

void set_color(int col)
{
	int attr;

	if (!use_colors)
		attr = (col & 0x70) ? A_REVERSE : 0;
	else {
		attr = (col & ATTR_COLOR8) ?
			(A_DIM | COLOR_PAIR(63)) :
			(COLOR_PAIR((col&7) + (col&0x70)/2));
	}

	if (col & 0x08) attr |= A_BOLD;
	if (col & 0x80) attr |= A_BLINK;

	if (col & ATTR_UNDERLINE) attr |= A_UNDERLINE;
	if (col & ATTR_REVERSE) attr |= A_REVERSE;

	attrset(attr);
}

void set_bg(int col)
{
	int attr;

	if (!use_colors)
		attr = (col & 0x70) ? A_REVERSE : 0;
	else {
		attr = (col == 8) ?
			(A_DIM | COLOR_PAIR(63)) :
			(COLOR_PAIR((col&7) + (col&0x70)/2));
	}

	if (col & 0x08) attr |= A_BOLD;
	if (col & 0x80) attr |= A_BLINK;

	bkgdset(' ' | attr);
}

/* Scroll area up */
void scroll_up(int y1, int y2)
{
	scrollok(stdscr, TRUE);
	setscrreg(y1, y2); scrl(1);
	scrollok(stdscr, FALSE);
}

/* Scroll area down */
void scroll_down(int y1, int y2)
{
	scrollok(stdscr, TRUE);
	setscrreg(y1, y2); scrl(-1);
	scrollok(stdscr, FALSE);
}

void move_cursor(int y, int x)
{
	scry = y;
	scrx = x;
}

void screen_refresh_freeze(void)
{
	freeze_refresh++;
}

void screen_refresh_thaw(void)
{
	if (freeze_refresh > 0) {
		freeze_refresh--;
		if (freeze_refresh == 0) screen_refresh();
	}
}

void screen_refresh(void)
{
	if (freeze_refresh == 0) {
		move(scry, scrx);
		refresh();
	}
}
