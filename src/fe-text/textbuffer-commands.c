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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/refstrings.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/fe-text/textbuffer-formats.h>

#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-text/gui-windows.h>

static int activity_hide_window_hidelevel;

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
			window = tmp->data;
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
	if (g_ascii_strcasecmp(data, "default") == 0) {
                gui->use_scroll = FALSE;
	} else if (g_ascii_strcasecmp(data, "on") == 0) {
		gui->use_scroll = TRUE;
		gui->scroll = TRUE;
	} else if (g_ascii_strcasecmp(data, "off") == 0) {
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

/* SYNTAX: WINDOW HIDELEVEL [<levels>] */
static void cmd_window_hidelevel(const char *data)
{
	GUI_WINDOW_REC *gui;
	char *level;

	g_return_if_fail(data != NULL);

	gui = WINDOW_GUI(active_win);
	textbuffer_view_set_hidden_level(gui->view,
					 combine_level(gui->view->hidden_level, data));
	textbuffer_view_redraw(gui->view);
	level = gui->view->hidden_level == 0 ? g_strdup("NONE") :
		bits2level(gui->view->hidden_level);
	printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
			   TXT_WINDOW_HIDELEVEL, level);
	g_free(level);
}

static void cmd_scrollback(const char *data, SERVER_REC *server,
			   WI_ITEM_REC *item)
{
	command_runsub("scrollback", data, server, item);
}

/* SYNTAX: SCROLLBACK CLEAR [-all] [<refnum>] */
static void cmd_scrollback_clear(const char *data)
{
	WINDOW_REC *window;
	GHashTable *optlist;
	char *refnum;
	void *free_arg;
	GSList *tmp;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "scrollback clear", &optlist, &refnum)) return;

	if (g_hash_table_lookup(optlist, "all") != NULL) {
		/* clear all windows */
		for (tmp = windows; tmp != NULL; tmp = tmp->next) {
			window = tmp->data;
			textbuffer_view_remove_all_lines(WINDOW_GUI(window)->view);
		}
	} else if (*refnum != '\0') {
		/* clear specified window */
		window = window_find_refnum(atoi(refnum));
		if (window != NULL)
			textbuffer_view_remove_all_lines(WINDOW_GUI(window)->view);
	} else {
		/* clear active window */
		textbuffer_view_remove_all_lines(WINDOW_GUI(active_win)->view);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: SCROLLBACK LEVELCLEAR [-all] [-level <level>] [<refnum>] */
static void cmd_scrollback_levelclear(const char *data)
{
	WINDOW_REC *window;
	GHashTable *optlist;
	char *refnum;
	void *free_arg;
	GSList *tmp;
	int level;
	char *levelarg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "scrollback levelclear", &optlist, &refnum)) return;

	levelarg = g_hash_table_lookup(optlist, "level");
	level = (levelarg == NULL || *levelarg == '\0') ? 0 :
		level2bits(replace_chars(levelarg, ',', ' '), NULL);
	if (level == 0) {
		cmd_params_free(free_arg);
		return;
	}

	if (g_hash_table_lookup(optlist, "all") != NULL) {
		/* clear all windows */
		for (tmp = windows; tmp != NULL; tmp = tmp->next) {
			window = tmp->data;
			textbuffer_view_remove_lines_by_level(WINDOW_GUI(window)->view, level);
		}
	} else if (*refnum != '\0') {
		/* clear specified window */
		window = window_find_refnum(atoi(refnum));
		if (window != NULL)
			textbuffer_view_remove_lines_by_level(WINDOW_GUI(window)->view, level);
	} else {
		/* clear active window */
		textbuffer_view_remove_lines_by_level(WINDOW_GUI(active_win)->view, level);
	}

	cmd_params_free(free_arg);
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

static void cmd_scrollback_status(void)
{
	GSList *tmp;
        int total_lines;
	size_t window_mem, total_mem;

        total_lines = 0; total_mem = 0;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;
		int i;
		LINE_REC *tmp;
		TEXT_BUFFER_VIEW_REC *view;

		view = WINDOW_GUI(window)->view;

		window_mem = sizeof(TEXT_BUFFER_REC);
		window_mem += view->buffer->lines_count * sizeof(LINE_REC);
		for (tmp = view->buffer->cur_line; tmp != NULL; tmp = tmp->prev) {
			if (tmp->info.text != NULL) {
				window_mem += sizeof(char) * (strlen(tmp->info.text) + 1);
			}
			if (tmp->info.format != NULL) {
				window_mem += sizeof(TEXT_BUFFER_FORMAT_REC);
				for (i = 0; i < tmp->info.format->nargs; i++) {
					if (tmp->info.format->args[i] != NULL) {
						window_mem +=
						    sizeof(char) *
						    (strlen(tmp->info.format->args[i]) + 1);
					}
				}
			}
		}
		total_lines += view->buffer->lines_count;
                total_mem += window_mem;
		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			  "Window %d: %d lines, %dkB of data",
			  window->refnum, view->buffer->lines_count,
			  (int)(window_mem / 1024));
	}

	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		  "Total: %d lines, %dkB of data",
		  total_lines, (int)(total_mem / 1024));
	{
		char *tmp = i_refstr_table_size_info();
		if (tmp != NULL)
			printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
				  "%s", tmp);
		g_free(tmp);
	}
}

/* SYNTAX: SCROLLBACK REDRAW */
static void cmd_scrollback_redraw(void)
{
	GUI_WINDOW_REC *gui;

	gui = WINDOW_GUI(active_win);

	term_refresh_freeze();
	textbuffer_view_reset_cache(gui->view);
	textbuffer_view_resize(gui->view, gui->view->width, gui->view->height);
	gui_window_redraw(active_win);
	term_refresh_thaw();
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

static void sig_window_hilight_check(TEXT_DEST_REC *dest, char *msg, int *data_level, int *ignore)
{
	GUI_WINDOW_REC *gui;

	g_return_if_fail(dest != NULL);
	g_return_if_fail(ignore != NULL);

	if (*ignore != 0 || !activity_hide_window_hidelevel || dest->window == NULL)
		return;

	gui = WINDOW_GUI(dest->window);

	if (dest->level & gui->view->hidden_level) {
		*ignore = TRUE;
	}
}

static void read_settings(void)
{
	activity_hide_window_hidelevel = settings_get_bool("activity_hide_window_hidelevel");
}

void textbuffer_commands_init(void)
{
	settings_add_bool("lookandfeel", "activity_hide_window_hidelevel", TRUE);

	command_bind("clear", NULL, (SIGNAL_FUNC) cmd_clear);
	command_bind("window scroll", NULL, (SIGNAL_FUNC) cmd_window_scroll);
	command_bind("window hidelevel", NULL, (SIGNAL_FUNC) cmd_window_hidelevel);
	command_bind("scrollback", NULL, (SIGNAL_FUNC) cmd_scrollback);
	command_bind("scrollback clear", NULL, (SIGNAL_FUNC) cmd_scrollback_clear);
	command_bind("scrollback levelclear", NULL, (SIGNAL_FUNC) cmd_scrollback_levelclear);
	command_bind("scrollback goto", NULL, (SIGNAL_FUNC) cmd_scrollback_goto);
	command_bind("scrollback home", NULL, (SIGNAL_FUNC) cmd_scrollback_home);
	command_bind("scrollback end", NULL, (SIGNAL_FUNC) cmd_scrollback_end);
	command_bind("scrollback status", NULL, (SIGNAL_FUNC) cmd_scrollback_status);
	command_bind("scrollback redraw", NULL, (SIGNAL_FUNC) cmd_scrollback_redraw);

	command_set_options("clear", "all");
	command_set_options("scrollback clear", "all");
	command_set_options("scrollback levelclear", "all -level");

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("away mode changed", (SIGNAL_FUNC) sig_away_changed);
	signal_add("window hilight check", (SIGNAL_FUNC) sig_window_hilight_check);
}

void textbuffer_commands_deinit(void)
{
	command_unbind("clear", (SIGNAL_FUNC) cmd_clear);
	command_unbind("window scroll", (SIGNAL_FUNC) cmd_window_scroll);
	command_unbind("window hidelevel", (SIGNAL_FUNC) cmd_window_hidelevel);
	command_unbind("scrollback", (SIGNAL_FUNC) cmd_scrollback);
	command_unbind("scrollback clear", (SIGNAL_FUNC) cmd_scrollback_clear);
	command_unbind("scrollback levelclear", (SIGNAL_FUNC) cmd_scrollback_levelclear);
	command_unbind("scrollback goto", (SIGNAL_FUNC) cmd_scrollback_goto);
	command_unbind("scrollback home", (SIGNAL_FUNC) cmd_scrollback_home);
	command_unbind("scrollback end", (SIGNAL_FUNC) cmd_scrollback_end);
	command_unbind("scrollback status", (SIGNAL_FUNC) cmd_scrollback_status);
	command_unbind("scrollback redraw", (SIGNAL_FUNC) cmd_scrollback_redraw);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("away mode changed", (SIGNAL_FUNC) sig_away_changed);
	signal_remove("window hilight check", (SIGNAL_FUNC) sig_window_hilight_check);
}
