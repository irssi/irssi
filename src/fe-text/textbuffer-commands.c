/*
 textbuffer-commands.c : Text buffer handling

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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "levels.h"
#include "settings.h"
#include "servers.h"

#include "printtext.h"
#include "gui-windows.h"
#include "textbuffer-reformat.h"
#ifdef HAVE_CUIX
#include "cuix.h"
#endif

/* SYNTAX: CLEAR [-all] [<refnum>] */
static void cmd_clear(const char *data)
{
        WINDOW_REC *window;
	GHashTable *optlist;
        char *refnum;
	void *free_arg;
        GSList *tmp;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "clear", &optlist, &refnum)) return;

	if (g_hash_table_lookup(optlist, "all") != NULL) {
                /* clear all windows */
		for (tmp = windows; tmp != NULL; tmp = tmp->next) {
			WINDOW_REC *window = tmp->data;

			textbuffer_view_clear(WINDOW_GUI(window)->view);
		}
	} else if (*refnum != '\0') {
                /* clear specified window */
		window = window_find_refnum(atoi(refnum));
                if (window != NULL)
			textbuffer_view_clear(WINDOW_GUI(window)->view);
	} else {
                /* clear active window */
		textbuffer_view_clear(WINDOW_GUI(active_win)->view);
	}

	cmd_params_free(free_arg);
}

static void cmd_window_scroll(const char *data)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(active_win);
	if (g_strcasecmp(data, "default") == 0) {
                gui->use_scroll = FALSE;
	} else if (g_strcasecmp(data, "on") == 0) {
		gui->use_scroll = TRUE;
		gui->scroll = TRUE;
	} else if (g_strcasecmp(data, "off") == 0) {
		gui->use_scroll = TRUE;
		gui->scroll = FALSE;
	} else if (*data != '\0') {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_WINDOW_SCROLL_UNKNOWN, data);
                return;
	}

	printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
			   TXT_WINDOW_SCROLL, !gui->use_scroll ? "DEFAULT" :
			   gui->scroll ? "ON" : "OFF");
	textbuffer_view_set_scroll(gui->view, gui->use_scroll ?
				   gui->scroll : settings_get_bool("scroll"));
}

static void cmd_scrollback(const char *data, SERVER_REC *server,
			   WI_ITEM_REC *item)
{
	command_runsub("scrollback", data, server, item);
}

/* SYNTAX: SCROLLBACK CLEAR */
static void cmd_scrollback_clear(void)
{
	textbuffer_view_remove_all_lines(WINDOW_GUI(active_win)->view);
}

static void scrollback_goto_line(int linenum)
{
        TEXT_BUFFER_VIEW_REC *view;

	view = WINDOW_GUI(active_win)->view;
	if (view->buffer->lines_count == 0)
		return;

	textbuffer_view_scroll_line(view, view->buffer->first_line);
	gui_window_scroll(active_win, linenum);
}

static void scrollback_goto_time(const char *datearg, const char *timearg)
{
        LINE_REC *line;
	struct tm tm;
	time_t now, stamp;
	int day, month;

	/* [dd[.mm] | -<days ago>] hh:mi[:ss] */
	now = stamp = time(NULL);
	if (*datearg == '-') {
		/* -<days ago> */
		stamp -= atoi(datearg+1) * 3600*24;
		memcpy(&tm, localtime(&stamp), sizeof(struct tm));
	} else if (*timearg != '\0') {
		/* dd[.mm] */
		memcpy(&tm, localtime(&stamp), sizeof(struct tm));

                day = month = 0;
		sscanf(datearg, "%d.%d", &day, &month);
		if (day <= 0) return;

		if (month <= 0) {
                        /* month not given */
			if (day > tm.tm_mday) {
                                /* last month's day */
				if (tm.tm_mon > 0)
					tm.tm_mon--;
				else {
                                        /* last year's day.. */
					tm.tm_year--;
                                        tm.tm_mon = 11;
				}
			}
		} else {
                        month--;
			if (month > tm.tm_mon)
				tm.tm_year--;
			tm.tm_mon = month;
		}

		tm.tm_mday = day;
		stamp = mktime(&tm);
	}
	else
	{
		/* only time given, move it to timearg */
		timearg = datearg;
	}

	/* hh:mi[:ss] */
	memcpy(&tm, localtime(&stamp), sizeof(struct tm));
	tm.tm_sec = 0;
	sscanf(timearg, "%d:%d:%d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	stamp = mktime(&tm);

	if (stamp > now && timearg == datearg) {
		/* we used /SB GOTO 23:59 or something, we want to jump to
		   previous day's 23:59 time instead of into future. */
		stamp -= 3600*24;
	}

	if (stamp > now) {
		/* we're still looking into future, don't bother checking */
		return;
	}

	/* scroll to first line after timestamp */
	line = textbuffer_view_get_lines(WINDOW_GUI(active_win)->view);
	for (; line != NULL; line = line->next) {
		if (line->info.time >= stamp) {
			gui_window_scroll_line(active_win, line);
			break;
		}
	}
}

/* SYNTAX: SCROLLBACK GOTO <+|-linecount>|<linenum>|<timestamp> */
static void cmd_scrollback_goto(const char *data)
{
	char *datearg, *timearg;
	void *free_arg;
	int lines;

	if (!cmd_get_params(data, &free_arg, 2, &datearg, &timearg))
		return;

	if (*timearg == '\0' && (*datearg == '-' || *datearg == '+')) {
		/* go forward/backward n lines */
                lines = atoi(datearg + (*datearg == '-' ? 0 : 1));
		gui_window_scroll(active_win, lines);
	} else if (*timearg == '\0' && is_numeric(datearg, '\0')) {
		/* go to n'th line. */
		scrollback_goto_line(atoi(datearg));
	} else {
                /* should be timestamp */
		scrollback_goto_time(datearg, timearg);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: SCROLLBACK HOME */
static void cmd_scrollback_home(const char *data)
{
        TEXT_BUFFER_REC *buffer;

	buffer = WINDOW_GUI(active_win)->view->buffer;
	if (buffer->lines_count > 0)
		gui_window_scroll_line(active_win, buffer->first_line);
}

/* SYNTAX: SCROLLBACK END */
static void cmd_scrollback_end(const char *data)
{
        TEXT_BUFFER_VIEW_REC *view;

	view = WINDOW_GUI(active_win)->view;
	if (view->bottom_startline == NULL ||
	    (view->bottom_startline == view->startline &&
	     view->bottom_subline == view->subline))
		return;

	textbuffer_view_scroll_line(view, view->bottom_startline);
	gui_window_scroll(active_win, view->bottom_subline);
}

/* SYNTAX: SCROLLBACK REDRAW */
static void cmd_scrollback_redraw(void)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *line, *next;

	gui = WINDOW_GUI(active_win);

	term_refresh_freeze();
	line = textbuffer_view_get_lines(gui->view);
	while (line != NULL) {
		next = line->next;
		textbuffer_reformat_line(active_win, line);
                line = next;
	}

	gui_window_redraw(active_win);
	term_refresh_thaw();
}

static void cmd_scrollback_status(void)
{
	GSList *tmp;
        int window_kb, total_lines, total_kb;

        total_lines = 0; total_kb = 0;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;
		TEXT_BUFFER_VIEW_REC *view;

		view = WINDOW_GUI(window)->view;

		window_kb = g_slist_length(view->buffer->text_chunks)*
			LINE_TEXT_CHUNK_SIZE/1024;
		total_lines += view->buffer->lines_count;
                total_kb += window_kb;
		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			  "Window %d: %d lines, %dkB of data",
			  window->refnum, view->buffer->lines_count,
			  window_kb);
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

                textbuffer_view_set_bookmark_bottom(WINDOW_GUI(rec)->view,
						    "lastlog_last_away");
	}
}

#ifdef HAVE_CUIX
static void cmd_cuix(void)
{
    if (!cuix_active)
    {
        /* textbuffer_view_clear(WINDOW_GUI(active_win)->view); */
        cuix_active = 1;
        cuix_create();
    } else {
        /* should never been called */
        /* cuix_destroy (); */
        cuix_active = 0;
        /* textbuffer_view_clear(WINDOW_GUI(active_win)->view); */
    }
}
#endif

void textbuffer_commands_init(void)
{
	command_bind("clear", NULL, (SIGNAL_FUNC) cmd_clear);
	command_bind("window scroll", NULL, (SIGNAL_FUNC) cmd_window_scroll);
	command_bind("scrollback", NULL, (SIGNAL_FUNC) cmd_scrollback);
	command_bind("scrollback clear", NULL, (SIGNAL_FUNC) cmd_scrollback_clear);
	command_bind("scrollback goto", NULL, (SIGNAL_FUNC) cmd_scrollback_goto);
	command_bind("scrollback home", NULL, (SIGNAL_FUNC) cmd_scrollback_home);
	command_bind("scrollback end", NULL, (SIGNAL_FUNC) cmd_scrollback_end);
	command_bind("scrollback redraw", NULL, (SIGNAL_FUNC) cmd_scrollback_redraw);
	command_bind("scrollback status", NULL, (SIGNAL_FUNC) cmd_scrollback_status);
#ifdef HAVE_CUIX
	command_bind("cuix", NULL, (SIGNAL_FUNC) cmd_cuix);
#endif

	command_set_options("clear", "all");

	signal_add("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}

void textbuffer_commands_deinit(void)
{
	command_unbind("clear", (SIGNAL_FUNC) cmd_clear);
	command_unbind("window scroll", (SIGNAL_FUNC) cmd_window_scroll);
	command_unbind("scrollback", (SIGNAL_FUNC) cmd_scrollback);
	command_unbind("scrollback clear", (SIGNAL_FUNC) cmd_scrollback_clear);
	command_unbind("scrollback goto", (SIGNAL_FUNC) cmd_scrollback_goto);
	command_unbind("scrollback home", (SIGNAL_FUNC) cmd_scrollback_home);
	command_unbind("scrollback end", (SIGNAL_FUNC) cmd_scrollback_end);
	command_unbind("scrollback redraw", (SIGNAL_FUNC) cmd_scrollback_redraw);
	command_unbind("scrollback status", (SIGNAL_FUNC) cmd_scrollback_status);
#ifdef HAVE_CUIX
	command_unbind("cuix", (SIGNAL_FUNC) cmd_cuix);
#endif

	signal_remove("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}
