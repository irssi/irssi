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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/fe-common/core/printtext.h>

#include <irssi/src/fe-text/gui-windows.h>
#include <irssi/src/fe-text/gui-printtext.h>

#define DEFAULT_LASTLOG_BEFORE 3
#define DEFAULT_LASTLOG_AFTER 3
#define MAX_LINES_WITHOUT_FORCE 1000

/* Only unknown keys in `optlist' should be levels.
   Returns -1 if unknown option was given. */
int cmd_options_get_level(const char *cmd, GHashTable *optlist)
{
	GList *list;
        int level, retlevel;

	list = optlist_remove_known(cmd, optlist);

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
                list = g_list_remove(list, list->data);
	}

	return retlevel;
}

static void prepend_date(WINDOW_REC *window, LINE_REC *rec, GString *line)
{
	THEME_REC *theme = NULL;
	TEXT_DEST_REC dest = {0};
	char *format = NULL, datestamp[20] = {0};
	struct tm *tm = localtime(&rec->info.time);
	int ret = 0;

	theme = window->theme != NULL ? window->theme : current_theme;
	format_create_dest(&dest, NULL, NULL, MSGLEVEL_LASTLOG, window);
	format = format_get_text_theme(theme, MODULE_NAME, &dest, TXT_LASTLOG_DATE);
 
	ret = strftime(datestamp, sizeof(datestamp), format, tm);
	g_free(format);
	if (ret <= 0) return;

	g_string_prepend(line, datestamp);
}

static void show_lastlog(const char *searchtext, GHashTable *optlist,
			 int start, int count, FILE *fhandle)
{
	WINDOW_REC *window;
        LINE_REC *startline;
	TEXT_BUFFER_VIEW_REC *view;
	TEXT_BUFFER_REC *buffer;
	GSList *texts, *tmp;
	GList *list, *tmp2;
	char *str;
	int level, before, after, len, date = FALSE;

        level = cmd_options_get_level("lastlog", optlist);
	if (level == -1) return; /* error in options */
        if (level == 0) level = MSGLEVEL_ALL;

	view = WINDOW_GUI(active_win)->view;
	if (g_hash_table_lookup(optlist, "clear") != NULL) {
		textbuffer_view_remove_lines_by_level(view, MSGLEVEL_LASTLOG);
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
	view = WINDOW_GUI(window)->view;

	if (g_hash_table_lookup(optlist, "new") != NULL)
		startline = textbuffer_view_get_bookmark(view, "lastlog_last_check");
	else if (g_hash_table_lookup(optlist, "away") != NULL)
		startline = textbuffer_view_get_bookmark(view, "lastlog_last_away");
	else
		startline = NULL;

	if (startline == NULL)
		startline = textbuffer_view_get_lines(view);

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

	if (g_hash_table_lookup(optlist, "date") != NULL)
		date = TRUE;

	buffer = view->buffer;
	list = textbuffer_find_text(buffer, startline, level, MSGLEVEL_LASTLOG, searchtext, before,
	                            after, g_hash_table_lookup(optlist, "regexp") != NULL,
	                            g_hash_table_lookup(optlist, "word") != NULL,
	                            g_hash_table_lookup(optlist, "case") != NULL);

	len = g_list_length(list);
	if (count <= 0)
		tmp2 = list;
	else {
		int pos = len-count-start;
		if (pos < 0) pos = 0;

		tmp2 = pos > len ? NULL : g_list_nth(list, pos);
		len = g_list_length(tmp2);
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

	/* collect the line texts */
	texts = NULL;
	for (; tmp2 != NULL && (count < 0 || count > 0); tmp2 = tmp2->next) {
		GString *line;
		LINE_REC *rec = tmp2->data;

		if (rec == NULL) {
			if (tmp2->next == NULL)
				break;
			texts = g_slist_prepend(texts, NULL);
			continue;
		}

		line = g_string_new(NULL);
		textbuffer_line2text(buffer, rec, fhandle == NULL, line);
		if (!settings_get_bool("timestamps")) {
			struct tm *tm = localtime(&rec->info.time);
                        char timestamp[10];

			g_snprintf(timestamp, sizeof(timestamp),
				   "%02d:%02d ",
				   tm->tm_hour, tm->tm_min);
                        g_string_prepend(line, timestamp);
		}

		if (date == TRUE)
			prepend_date(window, rec, line);

		texts = g_slist_prepend(texts, line);

		count--;
	}
	texts = g_slist_reverse(texts);

	if (fhandle == NULL && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_START);

	for (tmp = texts; tmp != NULL; tmp = tmp->next) {
		GString *line = tmp->data;

		if (line == NULL) {
			if (tmp->next == NULL)
				break;
			if (fhandle != NULL) {
				fwrite("--\n", 3, 1, fhandle);
			} else {
				printformat_window(active_win, MSGLEVEL_LASTLOG,
				                   TXT_LASTLOG_SEPARATOR);
			}
			continue;
		}

		/* write to file/window */
		if (fhandle != NULL) {
			fwrite(line->str, line->len, 1, fhandle);
			fputc('\n', fhandle);
		} else {
			printtext_window(active_win, MSGLEVEL_LASTLOG,
					 "%s", line->str);
		}
		g_string_free(line, TRUE);
	}

	if (fhandle == NULL && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_END);

	textbuffer_view_set_bookmark_bottom(view, "lastlog_last_check");

	g_slist_free(texts);
	g_list_free(list);
}

/* SYNTAX: LASTLOG [-] [-file <filename>] [-window <ref#|name>] [-new | -away]
		   [-<level> -<level...>] [-clear] [-count] [-case] [-date]
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

	command_set_options("lastlog", "!- # force clear -file -window new away word regexp case count date @a @after @before");
}

void lastlog_deinit(void)
{
	command_unbind("lastlog", (SIGNAL_FUNC) cmd_lastlog);
}
