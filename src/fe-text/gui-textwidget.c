/*
 gui-textwidget.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "commands.h"
#include "levels.h"

#include "printtext.h"
#include "gui-windows.h"

static void cmd_scrollback(gchar *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	command_runsub("scrollback", data, server, item);
}

/* SYNTAX: SCROLLBACK CLEAR */
static void cmd_scrollback_clear(gchar *data)
{
	gui_window_clear(active_win);
}

static void scrollback_goto_pos(WINDOW_REC *window, GList *pos)
{
	GUI_WINDOW_REC *gui;

	g_return_if_fail(window != NULL);
	g_return_if_fail(pos != NULL);

	gui = WINDOW_GUI(window);

	if (g_list_find(gui->bottom_startline, pos->data) == NULL) {
		gui->startline = pos;
		gui->subline = 0;
		gui_window_update_ypos(gui);
		gui->bottom = is_window_bottom(gui);
	} else {
		/* reached the last line */
		if (gui->bottom) return;

		gui->startline = gui->bottom_startline;
		gui->subline = gui->bottom_subline;
		gui->ypos = gui->parent->lines-1;
		gui->bottom = TRUE;
	}

	if (is_window_visible(window))
		gui_window_redraw(window);
	signal_emit("gui page scrolled", 1, window);
}

/* SYNTAX: SCROLLBACK GOTO <+|-linecount>|<linenum>|<timestamp> */
static void cmd_scrollback_goto(gchar *data)
{
    GList *pos;
    gchar *arg1, *arg2;
    void *free_arg;
    gint lines;

    if (!cmd_get_params(data, &free_arg, 2, &arg1, &arg2))
	    return;
    if (*arg2 == '\0' && (*arg1 == '-' || *arg1 == '+'))
    {
	/* go forward/backward n lines */
	if (sscanf(arg1 + (*arg1 == '-' ? 0 : 1), "%d", &lines) == 1)
	    gui_window_scroll(active_win, lines);
    }
    else if (*arg2 == '\0' && strchr(arg1, ':') == NULL && strchr(arg1, '.') == NULL &&
	     sscanf(arg1, "%d", &lines) == 1)
    {
        /* go to n'th line. */
	pos = g_list_nth(WINDOW_GUI(active_win)->lines, lines);
	if (pos != NULL)
            scrollback_goto_pos(active_win, pos);
    }
    else
    {
	struct tm tm;
	time_t stamp;
	gint day, month;

	/* [dd.mm | -<days ago>] hh:mi[:ss] */
	stamp = time(NULL);
	if (*arg1 == '-')
	{
	    /* -<days ago> */
	    if (sscanf(arg1+1, "%d", &day) == 1)
		stamp -= day*3600*24;
	    memcpy(&tm, localtime(&stamp), sizeof(struct tm));
	}
	else if (*arg2 != '\0')
	{
	    /* dd.mm */
	    if (sscanf(arg1, "%d.%d", &day, &month) == 2)
	    {
		month--;
		memcpy(&tm, localtime(&stamp), sizeof(struct tm));

		if (tm.tm_mon < month)
		    tm.tm_year--;
		tm.tm_mon = month;
		tm.tm_mday = day;
		stamp = mktime(&tm);
	    }
	}
	else
	{
            /* move time argument to arg2 */
	    arg2 = arg1;
	}

	/* hh:mi[:ss] */
	memcpy(&tm, localtime(&stamp), sizeof(struct tm));
        tm.tm_sec = 0;
	sscanf(arg2, "%d:%d:%d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	stamp = mktime(&tm);

	if (stamp > time(NULL) && arg1 == arg2) {
		/* we used /SB GOTO 23:59 or something, we want to jump to
		   previous day's 23:59 time instead of into future. */
                stamp -= 3600*24;
	}

	if (stamp > time(NULL)) {
		/* we're still looking into future, don't bother checking */
		cmd_params_free(free_arg);
		return;
	}

	/* find the first line after timestamp */
	for (pos = WINDOW_GUI(active_win)->lines; pos != NULL; pos = pos->next)
	{
	    LINE_REC *rec = pos->data;

	    if (rec->time >= stamp)
	    {
		scrollback_goto_pos(active_win, pos);
		break;
	    }
	}
    }
    cmd_params_free(free_arg);
}

/* SYNTAX: SCROLLBACK HOME */
static void cmd_scrollback_home(const char *data)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(active_win);

	if (gui->startline == gui->lines)
		return;

	gui->startline = gui->lines;
	gui->subline = 0;
	gui_window_update_ypos(gui);
	gui->bottom = is_window_bottom(gui);

	if (is_window_visible(active_win))
		gui_window_redraw(active_win);
	signal_emit("gui page scrolled", 1, active_win);
}

/* SYNTAX: SCROLLBACK END */
static void cmd_scrollback_end(const char *data)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(active_win);
	if (gui->bottom)
                return;

	gui->startline = gui->bottom_startline;
	gui->subline = gui->bottom_subline;
	gui->ypos = gui->parent->lines-1;
	gui->bottom = TRUE;

	if (is_window_visible(active_win))
		gui_window_redraw(active_win);
	signal_emit("gui page scrolled", 1, active_win);
}

/* SYNTAX: SCROLLBACK REDRAW */
static void cmd_scrollback_redraw(void)
{
	GUI_WINDOW_REC *gui;
	GList *tmp, *next;

	gui = WINDOW_GUI(active_win);

	screen_refresh_freeze();
	for (tmp = gui->lines; tmp != NULL; tmp = next) {
		next = tmp->next;
		gui_window_reformat_line(active_win, tmp->data);
	}

	gui_window_redraw(active_win);
	screen_refresh_thaw();
}

static void cmd_scrollback_status(void)
{
	GSList *tmp;
        int window_kb, total_lines, total_kb;

        total_lines = 0; total_kb = 0;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;
                GUI_WINDOW_REC *gui = WINDOW_GUI(window);

		window_kb = g_slist_length(gui->text_chunks)*
			LINE_TEXT_CHUNK_SIZE/1024;
		total_lines += window->lines;
                total_kb += window_kb;
		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			  "Window %d: %d lines, %dkB of data",
			  window->refnum, window->lines, window_kb);
	}

	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		  "Total: %d lines, %dkB of data",
		  total_lines, total_kb);
}

static void sig_away_changed(SERVER_REC *server)
{
	GSList *tmp;

	if (!server->usermode_away)
		return;

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *rec = tmp->data;

		WINDOW_GUI(rec)->lastlog_last_away =
			g_list_last(WINDOW_GUI(rec)->bottom_startline);
	}
}

void gui_textwidget_init(void)
{
	command_bind("scrollback", NULL, (SIGNAL_FUNC) cmd_scrollback);
	command_bind("scrollback clear", NULL, (SIGNAL_FUNC) cmd_scrollback_clear);
	command_bind("scrollback goto", NULL, (SIGNAL_FUNC) cmd_scrollback_goto);
	command_bind("scrollback home", NULL, (SIGNAL_FUNC) cmd_scrollback_home);
	command_bind("scrollback end", NULL, (SIGNAL_FUNC) cmd_scrollback_end);
	command_bind("scrollback redraw", NULL, (SIGNAL_FUNC) cmd_scrollback_redraw);
	command_bind("scrollback status", NULL, (SIGNAL_FUNC) cmd_scrollback_status);

	signal_add("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}

void gui_textwidget_deinit(void)
{
	command_unbind("scrollback", (SIGNAL_FUNC) cmd_scrollback);
	command_unbind("scrollback clear", (SIGNAL_FUNC) cmd_scrollback_clear);
	command_unbind("scrollback goto", (SIGNAL_FUNC) cmd_scrollback_goto);
	command_unbind("scrollback home", (SIGNAL_FUNC) cmd_scrollback_home);
	command_unbind("scrollback end", (SIGNAL_FUNC) cmd_scrollback_end);
	command_unbind("scrollback redraw", (SIGNAL_FUNC) cmd_scrollback_redraw);
	command_unbind("scrollback status", (SIGNAL_FUNC) cmd_scrollback_status);

	signal_remove("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}
