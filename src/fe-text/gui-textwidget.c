/*
 gui-textwidget.c : irssi

    Copyright (C) 1999 Timo Sirainen

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

#include "irc-servers.h"
#include "windows.h"
#include "printtext.h"

#include "screen.h"
#include "gui-windows.h"

static gchar *gui_window_line2text(LINE_REC *line)
{
    GString *str;
    gint color;
    gchar *ret, *ptr, *tmp;

    g_return_val_if_fail(line != NULL, NULL);

    str = g_string_new(NULL);

    color = 0;
    for (ptr = line->text; ; ptr++)
    {
	if (*ptr != 0)
	{
	    g_string_append_c(str, *ptr);
	    continue;
	}

	ptr++;
	if ((*ptr & 0x80) == 0)
	{
	    /* set color */
	    color = *ptr;
	    g_string_sprintfa(str, "\004%c%c", (color & 0x0f)+'0',
			      ((color & 0xf0) >> 4)+'0');
	}
	else switch ((guchar) *ptr)
	{
	    case LINE_CMD_EOL:
	    case LINE_CMD_FORMAT:
		ret = str->str;
		g_string_free(str, FALSE);
		return ret;
	    case LINE_CMD_CONTINUE:
		memcpy(&tmp, ptr+1, sizeof(gchar *));
		ptr = tmp-1;
		break;
	    case LINE_CMD_UNDERLINE:
		g_string_append_c(str, 31);
		break;
	    case LINE_CMD_COLOR0:
		g_string_sprintfa(str, "\004%c%c",
				  '0', ((color & 0xf0) >> 4)+'0');
		break;
	    case LINE_CMD_COLOR8:
		g_string_sprintfa(str, "\004%c%c",
				  '8', ((color & 0xf0) >> 4)+'0');
		color &= 0xfff0;
		color |= 8|ATTR_COLOR8;
		break;
	    case LINE_CMD_BLINK:
		color |= 0x80;
		g_string_sprintfa(str, "\004%c%c", (color & 0x0f)+'0',
				  ((color & 0xf0) >> 4)+'0');
		break;
	    case LINE_CMD_INDENT:
		break;
	}
    }

    return NULL;
}

#define LASTLOG_FLAG_NEW_LAST   0x01
#define LASTLOG_FLAG_NEW_AWAY   0x02
#define LASTLOG_FLAG_NOHEADERS  0x04
#define LASTLOG_FLAG_WORD       0x08
#define LASTLOG_FLAG_REGEXP     0x10

static int lastlog_parse_options(GHashTable *options, int *flags)
{
	GSList *list, *tmp;
	int level, optlevel;

	/* move all keys from `options' to linked list */
	list = hashtable_get_keys(options);

	/* level can be specified in arguments.. */
	level = 0; *flags = 0;
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		char *opt = tmp->data;

		if (strcmp(opt, "-") == 0)
			*flags |= LASTLOG_FLAG_NOHEADERS;
		else if (g_strcasecmp(opt, "new") == 0)
			*flags |= LASTLOG_FLAG_NEW_LAST;
		else if (g_strcasecmp(opt, "away") == 0)
			*flags |= LASTLOG_FLAG_NEW_AWAY;
		else if (g_strcasecmp(opt, "word") == 0)
			*flags |= LASTLOG_FLAG_WORD;
		else if (g_strcasecmp(opt, "regexp") == 0)
			*flags |= LASTLOG_FLAG_REGEXP;
		else {
			optlevel = level2bits(opt);
			if (optlevel != 0)
				level |= optlevel;
			else {
				signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_OPTION_UNKNOWN), opt);
                                level = -1;
				break;
			}
		}
	}
	if (level == 0) level = MSGLEVEL_ALL;

	g_slist_free(list);
	return level;
}

#define lastlog_match(line, level) \
	(((line)->level & level) != 0 && ((line)->level & MSGLEVEL_LASTLOG) == 0)

static GList *lastlog_find_startline(GList *list, int count, int start, int level)
{
	GList *tmp;

	if (count <= 0) return list;

	for (tmp = g_list_last(list); tmp != NULL; tmp = tmp->prev) {
		LINE_REC *rec = tmp->data;

		if (!lastlog_match(rec, level))
			continue;

		if (start > 0) {
			start--;
			continue;
		}

		if (--count == 0)
			return tmp;
	}

	return list;
}

/* SYNTAX: LASTLOG [-] [-new | -away] [-regexp | -word] [-<levels>]
	           [<pattern>] [<count> [<start>]] */
static void cmd_lastlog(const char *data)
{
	GHashTable *optlist;
	GList *startline, *list, *tmp;
	char *str, *text, *countstr, *start;
	void *free_arg;
	struct tm *tm;
	int level, flags, count;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_OPTIONS | PARAM_FLAG_UNKNOWN_OPTIONS,
			    "lastlog", &optlist, &text, &countstr, &start))
		return;

	if (*start == '\0' && is_numeric(text, 0)) {
		if (is_numeric(countstr, 0))
			start = countstr;
		countstr = text;
		text = "";
	}
	count = atoi(countstr);
	if (count == 0) count = -1;

	level = lastlog_parse_options(optlist, &flags);
	if (level == -1) {
		/* error in options */
		cmd_params_free(free_arg);
		return;
	}

	if ((flags & LASTLOG_FLAG_NOHEADERS) == 0)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, IRCTXT_LASTLOG_START);

	if (flags & LASTLOG_FLAG_NEW_LAST)
		startline = WINDOW_GUI(active_win)->lastlog_last_check;
	else if (flags & LASTLOG_FLAG_NEW_AWAY)
		startline = WINDOW_GUI(active_win)->lastlog_last_away;
	else
		startline = NULL;
	if (startline == NULL) startline = WINDOW_GUI(active_win)->lines;

	list = gui_window_find_text(active_win, text, startline, flags & LASTLOG_FLAG_REGEXP, flags & LASTLOG_FLAG_WORD);
	tmp = lastlog_find_startline(list, count, atoi(start), level);

	for (; tmp != NULL && (count < 0 || count > 0); tmp = tmp->next) {
		LINE_REC *rec = tmp->data;

		if (!lastlog_match(rec, level))
			continue;
		count--;

		text = gui_window_line2text(rec);
		if (settings_get_bool("timestamps"))
			printtext(NULL, NULL, MSGLEVEL_LASTLOG, "%s", text);
		else {
			tm = localtime(&rec->time);

			str = g_strdup_printf("[%02d:%02d] %s", tm->tm_hour, tm->tm_min, text);
			printtext(NULL, NULL, MSGLEVEL_LASTLOG, "%s", str);
			g_free(str);
		}
		g_free(text);
	}

	if ((flags & LASTLOG_FLAG_NOHEADERS) == 0)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, IRCTXT_LASTLOG_END);

	WINDOW_GUI(active_win)->lastlog_last_check =
		g_list_last(WINDOW_GUI(active_win)->bottom_startline);

	g_list_free(list);
	cmd_params_free(free_arg);
}

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

	gui->startline = gui->bottom_startline;
	gui->subline = gui->bottom_subline;
	gui->ypos = gui->parent->lines-1;
	gui->bottom = TRUE;

	if (is_window_visible(active_win))
		gui_window_redraw(active_win);
	signal_emit("gui page scrolled", 1, active_win);
}

static void sig_away_changed(IRC_SERVER_REC *server)
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
	command_bind("lastlog", NULL, (SIGNAL_FUNC) cmd_lastlog);
	command_bind("scrollback", NULL, (SIGNAL_FUNC) cmd_scrollback);
	command_bind("scrollback clear", NULL, (SIGNAL_FUNC) cmd_scrollback_clear);
	command_bind("scrollback goto", NULL, (SIGNAL_FUNC) cmd_scrollback_goto);
	command_bind("scrollback home", NULL, (SIGNAL_FUNC) cmd_scrollback_home);
	command_bind("scrollback end", NULL, (SIGNAL_FUNC) cmd_scrollback_end);
	command_set_options("lastlog", "!- new away word regexp");

	signal_add("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}

void gui_textwidget_deinit(void)
{
	command_unbind("lastlog", (SIGNAL_FUNC) cmd_lastlog);
	command_unbind("scrollback", (SIGNAL_FUNC) cmd_scrollback);
	command_unbind("scrollback clear", (SIGNAL_FUNC) cmd_scrollback_clear);
	command_unbind("scrollback goto", (SIGNAL_FUNC) cmd_scrollback_goto);
	command_unbind("scrollback home", (SIGNAL_FUNC) cmd_scrollback_home);
	command_unbind("scrollback end", (SIGNAL_FUNC) cmd_scrollback_end);

	signal_remove("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}
