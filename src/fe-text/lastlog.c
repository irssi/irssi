/*
 lastlog.c : irssi

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
#include "misc.h"
#include "levels.h"
#include "settings.h"

#include "module-formats.h"
#include "printtext.h"

#include "gui-windows.h"
#include "gui-printtext.h"

#define MAX_LINES_WITHOUT_FORCE 1000

static void window_lastlog_clear(WINDOW_REC *window)
{
	GList *tmp, *next;

	for (tmp = WINDOW_GUI(window)->lines; tmp != NULL; tmp = next) {
		LINE_REC *line = tmp->data;

                next = tmp->next;
                if (line->level & MSGLEVEL_LASTLOG)
			gui_window_line_remove(window, line, FALSE);
	}
        gui_window_redraw(window);
}

/* Only unknown keys in `optlist' should be levels.
   Returns -1 if unknown option was given. */
int cmd_options_get_level(const char *cmd, GHashTable *optlist)
{
	GSList *list, *tmp, *next;
        int level, retlevel;

	/* get all the options, then remove the known ones. there should
	   be only one left - the server tag. */
	list = hashtable_get_keys(optlist);
	if (cmd != NULL) {
		for (tmp = list; tmp != NULL; tmp = next) {
			char *option = tmp->data;
			next = tmp->next;

			if (command_have_option(cmd, option))
				list = g_slist_remove(list, option);
		}
	}

        retlevel = 0;
	while (list != NULL) {
		level = level_get(list->data);
		if (level == 0) {
			/* unknown option */
			signal_emit("error command", 2,
				    GINT_TO_POINTER(CMDERR_OPTION_UNKNOWN),
				    list->data);
			retlevel = -1;
                        break;
		}

		retlevel |= level;
                list = g_slist_remove(list, list->data);
	}

	return retlevel;
}

static void show_lastlog(const char *searchtext, GHashTable *optlist,
			 int start, int count)
{
        WINDOW_REC *window;
	GList *startline, *list, *tmp;
	GString *line;
        char *str;
	int level, fhandle, len;

        level = cmd_options_get_level("lastlog", optlist);
	if (level == -1) return; /* error in options */
        if (level == 0) level = MSGLEVEL_ALL;

	if (g_hash_table_lookup(optlist, "clear") != NULL) {
		window_lastlog_clear(active_win);
		if (*searchtext == '\0')
                        return;
	}

	/* target where to print it */
        fhandle = -1;
	str = g_hash_table_lookup(optlist, "file");
	if (str != NULL) {
                str = convert_home(str);
		fhandle = open(str, O_WRONLY | O_APPEND | O_CREAT,
			       octal2dec(settings_get_int("log_create_mode")));
                g_free(str);

		if (fhandle == -1) {
			printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
				  "%s", g_strerror(errno));
                        return;
		}
	}

	if (fhandle == -1 && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_START);

        /* which window's lastlog to look at? */
        window = active_win;
        str = g_hash_table_lookup(optlist, "window");
	if (str != NULL) {
		window = is_numeric(str, '\0') ?
			window_find_refnum(atoi(str)) :
			window_find_item(NULL, str);
	}

	if (g_hash_table_lookup(optlist, "new") != NULL)
		startline = WINDOW_GUI(window)->lastlog_last_check;
	else if (g_hash_table_lookup(optlist, "away") != NULL)
		startline = WINDOW_GUI(window)->lastlog_last_away;
	else
		startline = NULL;
	if (startline == NULL) startline = WINDOW_GUI(window)->lines;

	list = gui_window_find_text(window, startline,
				    level, MSGLEVEL_LASTLOG,
				    searchtext,
				    g_hash_table_lookup(optlist, "regexp") != NULL,
				    g_hash_table_lookup(optlist, "word") != NULL,
				    g_hash_table_lookup(optlist, "case") != NULL);

        len = g_list_length(list);
	if (count <= 0)
		tmp = list;
	else {
		int pos = len-count;

		if (pos < 0) pos = 0;
		pos += start;

		tmp = pos > len ? NULL : g_list_nth(list, pos);
		len = g_list_length(tmp);
	}

	if (len > MAX_LINES_WITHOUT_FORCE && fhandle == -1 &&
	    g_hash_table_lookup(optlist, "force") == NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_LASTLOG_TOO_LONG, len);
		g_list_free(list);
		return;
	}

	line = g_string_new(NULL);
        while (tmp != NULL && (count < 0 || count > 0)) {
		LINE_REC *rec = tmp->data;

                /* get the line text */
		gui_window_line2text(rec, fhandle == -1, line);
		if (!settings_get_bool("timestamps")) {
			struct tm *tm = localtime(&rec->time);
                        char timestamp[10];

			g_snprintf(timestamp, sizeof(timestamp),
				   "%02d:%02d ",
				   tm->tm_hour, tm->tm_min);
                        g_string_prepend(line, timestamp);
		}

                /* write to file/window */
		if (fhandle != -1) {
			write(fhandle, line->str, line->len);
			write(fhandle, "\n", 1);
		} else {
			printtext_window(active_win, MSGLEVEL_LASTLOG,
					 "%s", line->str);
		}

		count--;
		tmp = tmp->next;
	}
        g_string_free(line, TRUE);

	if (fhandle == -1 && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_END);

	if (fhandle != -1)
                close(fhandle);

	WINDOW_GUI(window)->lastlog_last_check =
		g_list_last(WINDOW_GUI(window)->bottom_startline);

	g_list_free(list);
}

/* SYNTAX: LASTLOG [-] [-file <filename>] [-clear] [-<level> -<level...>]
		   [-new | -away] [-regexp | -word] [-case]
		   [-window <ref#|name>] [<pattern>] [<count> [<start>]] */
static void cmd_lastlog(const char *data)
{
	GHashTable *optlist;
	char *text, *countstr, *start;
	void *free_arg;
        int count;

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

        show_lastlog(text, optlist, atoi(start), count);
	cmd_params_free(free_arg);
}

void lastlog_init(void)
{
	command_bind("lastlog", NULL, (SIGNAL_FUNC) cmd_lastlog);

	command_set_options("lastlog", "!- force clear -file -window new away word regexp case");
}

void lastlog_deinit(void)
{
	command_unbind("lastlog", (SIGNAL_FUNC) cmd_lastlog);
}
