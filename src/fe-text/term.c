/*
 term.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/fe-text/term.h>
#include <irssi/src/fe-text/mainwindows.h>

#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#include <signal.h>
#include <termios.h>

#define MIN_SCREEN_WIDTH 20

int term_width, term_height;

int term_use_colors;
int term_use_colors24;
int term_type;

static int force_colors;
static int resize_dirty;

int term_get_size(int *width, int *height)
{
#ifdef TIOCGWINSZ
	struct winsize ws;

	/* Get new window size */
	if (ioctl(0, TIOCGWINSZ, &ws) < 0)
		return FALSE;

	if (ws.ws_row == 0 && ws.ws_col == 0)
		return FALSE;

	*width = ws.ws_col;
        *height = ws.ws_row;

	if (*width < MIN_SCREEN_WIDTH)
		*width = MIN_SCREEN_WIDTH;
	if (*height < 1)
                *height = 1;
	return TRUE;
#else
        return FALSE;
#endif
}

/* Resize the terminal if needed */
void term_resize_dirty(void)
{
        int width, height;

	if (!resize_dirty)
		return;

        resize_dirty = FALSE;

	if (!term_get_size(&width, &height))
		width = height = -1;

	term_resize(width, height);
	mainwindows_resize(term_width, term_height);
	term_resize_final(width, height);
}

#ifdef SIGWINCH
static void sig_winch(int p)
{
        irssi_set_dirty();
        resize_dirty = TRUE;
}
#endif

static void cmd_resize(void)
{
	resize_dirty = TRUE;
        term_resize_dirty();
}

static void cmd_redraw(void)
{
	irssi_redraw();
}

int term_color256map[] = {
	 0, 4, 2, 6, 1, 5, 3, 7, 8,12,10,14, 9,13,11,15,
	 0, 0, 1, 1, 1, 1, 0, 0, 3, 1, 1, 9, 2, 2, 3, 3, 3, 3,
	 2, 2, 3, 3, 3, 3, 2, 2, 3, 3, 3,11,10,10, 3, 3,11,11,
	 0, 0, 5, 1, 1, 9, 0, 8, 8, 8, 9, 9, 2, 8, 8, 8, 9, 9,
	 2, 8, 8, 8, 9, 9, 2, 8, 8, 3, 3,11,10,10, 3, 3,11,11,
	 4, 4, 5, 5, 5, 5, 4, 8, 8, 8, 9, 9, 6, 8, 8, 8, 9, 9,
	 6, 8, 8, 8, 8, 9, 6, 8, 8, 8, 7, 7, 6, 6, 8, 7, 7, 7,
	 4, 4, 5, 5, 5, 5, 4, 8, 8, 8, 9, 9, 6, 8, 8, 8, 8, 9,
	 6, 8, 8, 8, 7, 7, 6, 6, 8, 7, 7, 7, 6, 6, 7, 7, 7, 7,
	 4, 4, 5, 5, 5,13, 4, 8, 8, 5, 5,13, 6, 8, 8, 8, 7, 7,
	 6, 6, 8, 7, 7, 7, 6, 6, 7, 7, 7, 7,14,14, 7, 7, 7, 7,
	12,12, 5, 5,13,13,12,12, 5, 5,13,13, 6, 6, 8, 7, 7, 7,
	 6, 6, 7, 7, 7, 7,14,14, 7, 7, 7, 7,14,14, 7, 7, 7,15,
	 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
	 7, 7, 7, 7, 7, 7, 0 };

static void read_settings(void)
{
        const char *str;
	int old_colors = term_use_colors;
	int old_colors24 = term_use_colors24;
        int old_type = term_type;

        /* set terminal type */
	str = settings_get_str("term_charset");
	if (g_ascii_strcasecmp(str, "utf-8") == 0)
		term_type = TERM_TYPE_UTF8;
	else if (g_ascii_strcasecmp(str, "big5") == 0)
		term_type = TERM_TYPE_BIG5;
	else
		term_type = TERM_TYPE_8BIT;

	if (old_type != term_type)
                term_set_input_type(term_type);

        /* change color stuff */
	if (force_colors != settings_get_bool("term_force_colors")) {
		force_colors = settings_get_bool("term_force_colors");
		term_force_colors(force_colors);
	}

	term_use_colors = settings_get_bool("colors") &&
		(force_colors || term_has_colors());

	term_use_colors24 = settings_get_bool("colors_ansi_24bit") &&
		(force_colors || term_has_colors());

	if (term_use_colors != old_colors || term_use_colors24 != old_colors24)
		irssi_redraw();
}

void term_common_init(void)
{
	const char *dummy;
#ifdef SIGWINCH
	struct sigaction act;
#endif
	settings_add_bool("lookandfeel", "colors", TRUE);
	settings_add_bool("lookandfeel", "term_force_colors", FALSE);
        settings_add_bool("lookandfeel", "mirc_blink_fix", FALSE);

	force_colors = FALSE;
	term_use_colors = term_has_colors() && settings_get_bool("colors");
	settings_add_bool("lookandfeel", "colors_ansi_24bit", FALSE);
	term_use_colors24 = term_has_colors() && settings_get_bool("colors_ansi_24bit");
        read_settings();

	if (g_get_charset(&dummy)) {
		term_type = TERM_TYPE_UTF8;
		term_set_input_type(TERM_TYPE_UTF8);
	}

	signal_add("beep", (SIGNAL_FUNC) term_beep);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	command_bind("resize", NULL, (SIGNAL_FUNC) cmd_resize);
	command_bind("redraw", NULL, (SIGNAL_FUNC) cmd_redraw);

#ifdef SIGWINCH
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sig_winch;
	sigaction(SIGWINCH, &act, NULL);
#endif
}

void term_common_deinit(void)
{
	command_unbind("resize", (SIGNAL_FUNC) cmd_resize);
	command_unbind("redraw", (SIGNAL_FUNC) cmd_redraw);
	signal_remove("beep", (SIGNAL_FUNC) term_beep);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
