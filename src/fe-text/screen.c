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

#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif

#ifndef COLOR_PAIRS
#define COLOR_PAIRS 64
#endif

#define MIN_SCREEN_WIDTH 20

struct _SCREEN_WINDOW {
        WINDOW *win;
};

SCREEN_WINDOW *screen_root;
int screen_width, screen_height;

static int scrx, scry;
static int use_colors;
static int freeze_refresh;

static int init_screen_int(void);
static void deinit_screen_int(void);

#ifdef SIGWINCH

static void sig_winch(int p)
{
#if defined (TIOCGWINSZ) && defined (HAVE_CURSES_RESIZETERM)
	struct winsize ws;

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
	resizeterm(ws.ws_row, ws.ws_col);

	screen_width = COLS;
	screen_height = LINES;
#else
	deinit_screen_int();
	init_screen_int();
	mainwindows_recreate();
#endif

	mainwindows_resize(COLS, LINES);
}
#endif

static void read_settings(void)
{
	int old_colors = use_colors;

	use_colors = settings_get_bool("colors");
	if (use_colors && !has_colors())
		use_colors = FALSE;

	if (use_colors != old_colors)
		irssi_redraw();
}

static int init_curses(void)
{
	char ansi_tab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	int num;
#ifndef WIN32
	struct sigaction act;
#endif

	if (!initscr())
		return FALSE;

	if (COLS < MIN_SCREEN_WIDTH)
		COLS = MIN_SCREEN_WIDTH;

#ifdef SIGWINCH
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sig_winch;
	sigaction(SIGWINCH, &act, NULL);
#endif
	raw(); noecho(); idlok(stdscr, 1);
#ifdef HAVE_CURSES_IDCOK
	idcok(stdscr, 1);
#endif
	intrflush(stdscr, FALSE); nodelay(stdscr, TRUE);

	if (has_colors())
		start_color();
	else if (use_colors)
                use_colors = FALSE;

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

	clear();
	return TRUE;
}

static int init_screen_int(void)
{
	int ret;

	ret = init_curses();
	if (!ret) return 0;

	use_colors = settings_get_bool("colors");

	scrx = scry = 0;
	freeze_refresh = 0;

	screen_root = g_new0(SCREEN_WINDOW, 1);
        screen_root->win = stdscr;

	screen_width = COLS;
	screen_height = LINES;
        return ret;
}

static void deinit_screen_int(void)
{
	endwin();
	g_free_and_null(screen_root);
}

/* Initialize screen, detect screen length */
int init_screen(void)
{
	settings_add_bool("lookandfeel", "colors", TRUE);

	signal_add("beep", (SIGNAL_FUNC) beep);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

        return init_screen_int();
}

/* Deinitialize screen */
void deinit_screen(void)
{
	deinit_screen_int();

	signal_remove("beep", (SIGNAL_FUNC) beep);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}

int screen_has_colors(void)
{
        return has_colors();
}

void screen_clear(void)
{
        clear();
}

SCREEN_WINDOW *screen_window_create(int x, int y, int width, int height)
{
        SCREEN_WINDOW *scrwin;

	scrwin = g_new0(SCREEN_WINDOW, 1);
	scrwin->win = newwin(height, width, y, x);
	idlok(scrwin->win, 1);

        return scrwin;
}

void screen_window_destroy(SCREEN_WINDOW *window)
{
	delwin(window->win);
        g_free(window);
}

void screen_window_clear(SCREEN_WINDOW *window)
{
        werase(window->win);
}

void screen_window_move(SCREEN_WINDOW *window, int x, int y,
			int width, int height)
{
#ifdef HAVE_CURSES_WRESIZE
	wresize(window->win, height, width);
	mvwin(window->win, y, x);
#else
	delwin(window->win);
	window->win = newwin(height, width, y, x);
	idlok(window->win, 1);
#endif
}

void screen_window_scroll(SCREEN_WINDOW *window, int count)
{
	scrollok(window->win, TRUE);
	wscrl(window->win, count);
	scrollok(window->win, FALSE);
}

void screen_set_color(SCREEN_WINDOW *window, int col)
{
	int attr;

	if (!use_colors)
		attr = (col & 0x70) ? A_REVERSE : 0;
	else if (col & ATTR_COLOR8)
                attr = (A_DIM | COLOR_PAIR(63));
	else if ((col & 0x77) == 0)
		attr = A_NORMAL;
	else
		attr = (COLOR_PAIR((col&7) + (col&0x70)/2));

	if (col & 0x08) attr |= A_BOLD;
	if (col & 0x80) attr |= A_BLINK;

	if (col & ATTR_UNDERLINE) attr |= A_UNDERLINE;
	if (col & ATTR_REVERSE) attr |= A_REVERSE;

	wattrset(window->win, attr);
}

void screen_set_bg(SCREEN_WINDOW *window, int col)
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

	wbkgdset(window->win, ' ' | attr);
}

void screen_move(SCREEN_WINDOW *window, int x, int y)
{
        wmove(window->win, y, x);
}

void screen_addch(SCREEN_WINDOW *window, int chr)
{
        waddch(window->win, chr);
}

void screen_addstr(SCREEN_WINDOW *window, char *str)
{
        waddstr(window->win, str);
}

void screen_clrtoeol(SCREEN_WINDOW *window)
{
        wclrtoeol(window->win);
}

void screen_move_cursor(int x, int y)
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
		if (freeze_refresh == 0) screen_refresh(NULL);
	}
}

void screen_refresh(SCREEN_WINDOW *window)
{
	if (window != NULL)
		wnoutrefresh(window->win);

	if (freeze_refresh == 0) {
		move(scry, scrx);
		wnoutrefresh(stdscr);
		doupdate();
	}
}

int screen_getch(void)
{
	int key;

	key = getch();
	if (key == ERR)
		return -1;

#ifdef KEY_RESIZE
	if (key == KEY_RESIZE)
                return -1;
#endif

	return key;
}
