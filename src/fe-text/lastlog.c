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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#define DEFAULT_LASTLOG_BEFORE 3
#define DEFAULT_LASTLOG_AFTER 3
#define MAX_LINES_WITHOUT_FORCE 1000

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
			 int start, int count, FILE *fhandle)
{
	WINDOW_REC *window;
        LINE_REC *startline;
	GList *list, *tmp;
	GString *line;
        char *str;
	int level, before, after, len;

        level = cmd_options_get_level("lastlog", optlist);
	if (level == -1) return; /* error in options */
        if (level == 0) level = MSGLEVEL_ALL;

	if (g_hash_table_lookup(optlist, "clear") != NULL) {
		textbuffer_view_remove_lines_by_level(WINDOW_GUI(active_win)->view, MSGLEVEL_LASTLOG);
		if (*searchtext == '\0')
                        return;
	}

        /* which window's lastlog to look at? */
        window = active_win;
        str = g_hash_table_lookup(optlist, "window");
	if (str != NULL) {
		window = is_numeric(str, '\0') ?
			window_find_refnum(atoi(str)) :
			window_find_item(NULL, str);
		if (window == NULL) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
                                    TXT_REFNUM_NOT_FOUND, str);
			return;
		}
	}

	if (g_hash_table_lookup(optlist, "new") != NULL)
		startline = textbuffer_view_get_bookmark(WINDOW_GUI(window)->view, "lastlog_last_check");
	else if (g_hash_table_lookup(optlist, "away") != NULL)
		startline = textbuffer_view_get_bookmark(WINDOW_GUI(window)->view, "lastlog_last_away");
	else
		startline = NULL;

	if (startline == NULL)
                startline = textbuffer_view_get_lines(WINDOW_GUI(window)->view);

	str = g_hash_table_lookup(optlist, "#");
	if (str != NULL) {
		before = after = atoi(str);
	} else {
		str = g_hash_table_lookup(optlist, "before");
		before = str == NULL ? 0 : *str != '\0' ?
			atoi(str) : DEFAULT_LASTLOG_BEFORE;

		str = g_hash_table_lookup(optlist, "after");
		if (str == NULL) str = g_hash_table_lookup(optlist, "a");
		after = str == NULL ? 0 : *str != '\0' ?
			atoi(str) : DEFAULT_LASTLOG_AFTER;
	}

	list = textbuffer_find_text(WINDOW_GUI(window)->view->buffer, startline,
				    level, MSGLEVEL_LASTLOG,
				    searchtext, before, after,
				    g_hash_table_lookup(optlist, "regexp") != NULL,
				    g_hash_table_lookup(optlist, "word") != NULL,
				    g_hash_table_lookup(optlist, "case") != NULL);

        len = g_list_length(list);
	if (count <= 0)
		tmp = list;
	else {
		int pos = len-count-start;
		if (pos < 0) pos = 0;

		tmp = pos > len ? NULL : g_list_nth(list, pos);
		len = g_list_length(tmp);
	}

	if (g_hash_table_lookup(optlist, "count") != NULL) {
		printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
				   TXT_LASTLOG_COUNT, len);
		g_list_free(list);
		return;
	}

	if (len > MAX_LINES_WITHOUT_FORCE && fhandle == NULL &&
	    g_hash_table_lookup(optlist, "force") == NULL) {
		printformat_window(active_win,
				   MSGLEVEL_CLIENTNOTICE|MSGLEVEL_LASTLOG,
				   TXT_LASTLOG_TOO_LONG, len);
		g_list_free(list);
		return;
	}

	if (fhandle == NULL && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_START);

	line = g_string_new(NULL);
        while (tmp != NULL && (count < 0 || count > 0)) {
		LINE_REC *rec = tmp->data;

		if (rec == NULL) {
			if (tmp->next == NULL)
                                break;
			if (fhandle != NULL) {
				fwrite("--\n", 3, 1, fhandle);
			} else {
				printformat_window(active_win,
						   MSGLEVEL_LASTLOG,
						   TXT_LASTLOG_SEPARATOR);
			}
                        tmp = tmp->next;
			continue;
		}

                /* get the line text */
		textbuffer_line2text(rec, fhandle == NULL, line);
		if (!settings_get_bool("timestamps")) {
			struct tm *tm = localtime(&rec->info.time);
                        char timestamp[10];

			g_snprintf(timestamp, sizeof(timestamp),
				   "%02d:%02d ",
				   tm->tm_hour, tm->tm_min);
                        g_string_prepend(line, timestamp);
		}

                /* write to file/window */
		if (fhandle != NULL) {
			fwrite(line->str, line->len, 1, fhandle);
			fputc('\n', fhandle);
		} else {
			printtext_window(active_win, MSGLEVEL_LASTLOG,
					 "%s", line->str);
		}

		count--;
		tmp = tmp->next;
	}
        g_string_free(line, TRUE);

	if (fhandle == NULL && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_END);

	textbuffer_view_set_bookmark_bottom(WINDOW_GUI(window)->view,
					    "lastlog_last_check");

	g_list_free(list);
}

/* SYNTAX: LASTLOG [-] [-file <filename>] [-window <ref#|name>] [-new | -away]
		   [-<level> -<level...>] [-clear] [-count] [-case]
		   [-regexp | -word] [-before [<#>]] [-after [<#>]]
		   [-<# before+after>] [<pattern>] [<count> [<start>]] */
static void cmd_lastlog(const char *data)
{
	GHashTable *optlist;
	char *text, *countstr, *start, *fname;
	void *free_arg;
        int count, fd;
	FILE *fhandle;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS, "lastlog", &optlist,
			    &text, &countstr, &start))
		return;

	if (*start == '\0' && is_numeric(text, 0) && *text != '0' &&
	    (*countstr == '\0' || is_numeric(countstr, 0))) {
		start = countstr;
		countstr = text;
		text = "";
	}
	count = atoi(countstr);
	if (count == 0) count = -1;

	/* target where to print it */
        fhandle = NULL;
	fname = g_hash_table_lookup(optlist, "file");
	if (fname != NULL) {
                fname = convert_home(fname);
		fd = open(fname, O_WRONLY | O_APPEND | O_CREAT,
			  octal2dec(settings_get_int("log_create_mode")));
		if (fd != -1) {
			fhandle = fdopen(fd, "a");
			if (fhandle == NULL)
				close(fd);
		}
                g_free(fname);
	}

	if (fname != NULL && fhandle == NULL) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "Could not open lastlog: %s", g_strerror(errno));
	} else {
		show_lastlog(text, optlist, atoi(start), count, fhandle);
		if (fhandle != NULL) {
			if (ferror(fhandle))
				printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
				  	  "Could not write lastlog: %s", g_strerror(errno));
			fclose(fhandle);
		}
	}

	cmd_params_free(free_arg);
}

void lastlog_init(void)
{
	command_bind("lastlog", NULL, (SIGNAL_FUNC) cmd_lastlog);

	command_set_options("lastlog", "!- # force clear -file -window new away word regexp case count @a @after @before");
}

void lastlog_deinit(void)
{
	command_unbind("lastlog", (SIGNAL_FUNC) cmd_lastlog);
}
