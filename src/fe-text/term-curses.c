/*
 term-curses.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "settings.h"

#include "term.h"
#include "mainwindows.h"

#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif
#include <termios.h>
#include <signal.h>

#ifndef COLOR_PAIRS
#  define COLOR_PAIRS 64
#endif

#if defined (TIOCGWINSZ) && defined (HAVE_CURSES_RESIZETERM)
#  define USE_RESIZE_TERM
#endif

#ifndef _POSIX_VDISABLE
#  define _POSIX_VDISABLE 0
#endif

struct _TERM_WINDOW {
	int x, y;
        int width, height;
	WINDOW *win;
};

TERM_WINDOW *root_window;

static int curs_x, curs_y;
static int freeze_refresh;
static struct termios old_tio;

static int init_curses(void)
{
	char ansi_tab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	int num;
        struct termios tio;

	if (!initscr())
		return FALSE;

	cbreak(); noecho(); idlok(stdscr, 1);
#ifdef HAVE_CURSES_IDCOK
	/*idcok(stdscr, 1); - disabled currently, causes redrawing problems with NetBSD */
#endif
	intrflush(stdscr, FALSE); nodelay(stdscr, TRUE);

        /* Disable INTR, QUIT, VDSUSP and SUSP keys */
	if (tcgetattr(0, &old_tio) == 0) {
                memcpy(&tio, &old_tio, sizeof(tio));
		tio.c_cc[VINTR] = _POSIX_VDISABLE;
                tio.c_cc[VQUIT] = _POSIX_VDISABLE;
#ifdef VDSUSP
		tio.c_cc[VDSUSP] = _POSIX_VDISABLE;
#endif
#ifdef VSUSP
		tio.c_cc[VSUSP] = _POSIX_VDISABLE;
#endif
		tcsetattr(0, TCSADRAIN, &tio);
	}

	if (has_colors())
		start_color();
	else if (term_use_colors)
                term_use_colors = FALSE;

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

static int term_init_int(void)
{
	int ret;

	ret = init_curses();
	if (!ret) return 0;

        curs_x = curs_y = 0;
	freeze_refresh = 0;

	root_window = g_new0(TERM_WINDOW, 1);
        root_window->win = stdscr;

	term_width = COLS;
	term_height = LINES;
        return ret;
}

static void term_deinit_int(void)
{
        tcsetattr(0, TCSADRAIN, &old_tio);

	endwin();
	g_free_and_null(root_window);
}

int term_init(void)
{
	if (!term_init_int())
                return FALSE;

        settings_add_int("lookandfeel", "default_color", 7);
	term_common_init();
        return TRUE;
}

void term_deinit(void)
{
        term_common_deinit();
	term_deinit_int();
}

/* Resize terminal - if width or height is negative,
   the new size is unknown and should be figured out somehow */
void term_resize(int width, int height)
{
#ifdef HAVE_CURSES_RESIZETERM
	if (width < 0 || height < 0) {
#endif
		term_deinit_int();
		term_init_int();
#ifdef HAVE_CURSES_RESIZETERM
	} else if (term_width != width || term_height != height) {
		term_width = width;
		term_height = height;
                resizeterm(term_height, term_width);
	}
#endif
}

void term_resize_final(int width, int height)
{
#ifdef HAVE_CURSES_RESIZETERM
        if (width < 0 || height < 0)
		mainwindows_recreate();
#else
	mainwindows_recreate();
#endif
}

/* Returns TRUE if terminal has colors */
int term_has_colors(void)
{
        return has_colors();
}

/* Force the colors on any way you can */
void term_force_colors(int set)
{
        /* don't do anything with curses */
}

/* Clear screen */
void term_clear(void)
{
        term_set_color(root_window, 0);
        clear();
}

/* Beep */
void term_beep(void)
{
        beep();
}

/* Create a new window in terminal */
TERM_WINDOW *term_window_create(int x, int y, int width, int height)
{
        TERM_WINDOW *window;

	window = g_new0(TERM_WINDOW, 1);
	window->x = x; window->y = y;
        window->width = width; window->height = height;
	window->win = newwin(height, width, y, x);
	if (window->win == NULL)
		g_error("newwin() failed: %d,%d %d,%d", x, y, width, height);
	idlok(window->win, 1);

        return window;
}

/* Destroy a terminal window */
void term_window_destroy(TERM_WINDOW *window)
{
	delwin(window->win);
        g_free(window);
}

/* Move/resize a window */
void term_window_move(TERM_WINDOW *window, int x, int y,
		      int width, int height)
{
	/* some checks to make sure the window is visible in screen,
	   otherwise curses could get nasty and not show our window anymore. */
        if (width < 1) width = 1;
	if (height < 1) height = 1;
	if (x+width > term_width) x = term_width-width;
	if (y+height > term_height) y = term_height-height;

#ifdef HAVE_CURSES_WRESIZE
	if (window->width != width || window->height != height)
		wresize(window->win, height, width);
        if (window->x != x || window->y != y)
		mvwin(window->win, y, x);
#else
	if (window->width != width || window->height != height ||
	    window->x != x || window->y != y) {
		delwin(window->win);
		window->win = newwin(height, width, y, x);
		idlok(window->win, 1);
	}
#endif
        window->x = x; window->y = y;
        window->width = width; window->height = height;
}

/* Clear window */
void term_window_clear(TERM_WINDOW *window)
{
        werase(window->win);
}

/* Scroll window up/down */
void term_window_scroll(TERM_WINDOW *window, int count)
{
	scrollok(window->win, TRUE);
	wscrl(window->win, count);
	scrollok(window->win, FALSE);
}

static int get_attr(int color)
{
	int attr;

	if (!term_use_colors)
		attr = (color & 0x70) ? A_REVERSE : 0;
	else if ((color & 0xff) == 8 || (color & (0xff | ATTR_RESETFG)) == 0)
		attr = COLOR_PAIR(63);
	else if ((color & 0x77) == 0)
		attr = A_NORMAL;
	else {
		if (color & ATTR_RESETFG) {
			color &= ~0x0f;
			color |= settings_get_int("default_color");
		}
		attr = COLOR_PAIR((color&7) | ((color&0x70)>>1));
	}

	if ((color & 0x08) || (color & ATTR_BOLD)) attr |= A_BOLD;
	if (color & ATTR_BLINK) attr |= A_BLINK;

	if (color & ATTR_UNDERLINE) attr |= A_UNDERLINE;
	if (color & ATTR_REVERSE) attr |= A_REVERSE;
        return attr;
}

/* Change active color */
void term_set_color(TERM_WINDOW *window, int col)
{
	wattrset(window->win, get_attr(col));
	wbkgdset(window->win, ' ' | get_attr(col));
}

void term_move(TERM_WINDOW *window, int x, int y)
{
        wmove(window->win, y, x);
}

void term_addch(TERM_WINDOW *window, char chr)
{
        waddch(window->win, chr);
}

void term_add_unichar(TERM_WINDOW *window, unichar chr)
{
#ifdef WIDEC_CURSES
	cchar_t wch;
	wchar_t temp[2];
	temp[0] = chr;
	temp[1] = 0;
	if (setcchar(&wch, temp, A_NORMAL, 0, NULL) == OK)
		wadd_wch(window->win, &wch);
	else
#endif
        waddch(window->win, chr);
}

void term_addstr(TERM_WINDOW *window, const char *str)
{
        waddstr(window->win, (const char *) str);
}

void term_clrtoeol(TERM_WINDOW *window)
{
        wclrtoeol(window->win);
}

void term_move_cursor(int x, int y)
{
	curs_x = x;
        curs_y = y;
}

void term_refresh_freeze(void)
{
	freeze_refresh++;
}

void term_refresh_thaw(void)
{
	if (freeze_refresh > 0) {
		freeze_refresh--;
		if (freeze_refresh == 0) term_refresh(NULL);
	}
}

void term_refresh(TERM_WINDOW *window)
{
	if (window != NULL)
		wnoutrefresh(window->win);

	if (freeze_refresh == 0) {
		move(curs_y, curs_x);
		wnoutrefresh(stdscr);
		doupdate();
	}
}

void term_stop(void)
{
	term_deinit_int();
	kill(getpid(), SIGTSTP);
        term_init_int();
	irssi_redraw();
}

void term_set_input_type(int type)
{
}

void term_gets(GArray *buffer, int *line_count)
{
#ifdef WIDEC_CURSES
	wint_t key;
#else
	int key;
#endif

	for (;;) {
#ifdef WIDEC_CURSES
		if (get_wch(&key) == ERR)
#else
		if ((key = getch()) == ERR)
#endif
			break;
#ifdef KEY_RESIZE
		if (key == KEY_RESIZE)
			continue;
#endif

		g_array_append_val(buffer, key);
		if (key == '\r' || key == '\n')
			(*line_count)++;
	}
}
