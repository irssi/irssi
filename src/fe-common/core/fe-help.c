/*
 fe-help.c : irssi

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
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/formats.h>

static int commands_equal(COMMAND_REC *rec, COMMAND_REC *rec2)
{
	int i;

	if (rec->category == NULL && rec2->category != NULL)
		return -1;
	if (rec2->category == NULL && rec->category != NULL)
		return 1;
	if (rec->category != NULL && rec2->category != NULL) {
		i = g_strcmp0(rec->category, rec2->category);
		if (i != 0)
			return i;
	}

	return g_strcmp0(rec->cmd, rec2->cmd);
}

static int get_cmd_length(void *data)
{
        return strlen(((COMMAND_REC *) data)->cmd);
}

static void help_category(GSList *cmdlist, int items)
{
        WINDOW_REC *window;
	TEXT_DEST_REC dest;
	GString *str;
	GSList *tmp;
	int *columns, cols, rows, col, row, last_col_rows, max_width;
	char *linebuf, *format, *stripped;

	window = window_find_closest(NULL, NULL, MSGLEVEL_CLIENTCRAP);
        max_width = window->width;

        /* remove width of timestamp from max_width */
	format_create_dest(&dest, NULL, NULL, MSGLEVEL_CLIENTCRAP, NULL);
	format = format_get_line_start(current_theme, &dest, time(NULL));
	if (format != NULL) {
		stripped = strip_codes(format);
		max_width -= strlen(stripped);
		g_free(stripped);
		g_free(format);
	}

        /* calculate columns */
	cols = get_max_column_count(cmdlist, get_cmd_length,
				    max_width, 6, 1, 3, &columns, &rows);
	cmdlist = columns_sort_list(cmdlist, rows);

	/* if the screen is too narrow the window width may be not
	   enough for even 1 column */
	if (cols == 1 && columns[0] > max_width)
		max_width = columns[0];

	/* rows in last column */
	last_col_rows = rows-(cols*rows-g_slist_length(cmdlist));
	if (last_col_rows == 0)
                last_col_rows = rows;

	str = g_string_new(NULL);
	linebuf = g_malloc(max_width+1);

        col = 0; row = 0;
	for (tmp = cmdlist; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		memset(linebuf, ' ', columns[col]);
		linebuf[columns[col]] = '\0';
		memcpy(linebuf, rec->cmd, strlen(rec->cmd));
		g_string_append(str, linebuf);

		if (++col == cols) {
			printtext(NULL, NULL,
				  MSGLEVEL_CLIENTCRAP, "%s", str->str);
			g_string_truncate(str, 0);
			col = 0; row++;

			if (row == last_col_rows)
                                cols--;
		}
	}
	if (str->len != 0)
		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s", str->str);

	g_slist_free(cmdlist);
	g_string_free(str, TRUE);
	g_free(columns);
	g_free(linebuf);
}

static int show_help_file(const char *file)
{
        const char *helppath;
	char *path, **paths, **tmp;
	GIOChannel *handle;
	GString *buf;
	gsize tpos;

        helppath = settings_get_str("help_path");

	paths = g_strsplit(helppath, ":", -1);

	handle = NULL;
	for (tmp = paths; *tmp != NULL; tmp++) {
		/* helpdir/command or helpdir/category/command */
		path = g_strdup_printf("%s/%s", *tmp, file);
		handle = g_io_channel_new_file(path, "r", NULL);
		g_free(path);

		if (handle != NULL)
			break;

	}

	g_strfreev(paths);

	if (handle == NULL)
		return FALSE;

	g_io_channel_set_encoding(handle, NULL, NULL);
	buf = g_string_sized_new(512);
	/* just print to screen whatever is in the file */
	while (g_io_channel_read_line_string(handle, buf, &tpos, NULL) == G_IO_STATUS_NORMAL) {
		buf->str[tpos] = '\0';
		g_string_prepend(buf, "%|");
		printtext_string(NULL, NULL, MSGLEVEL_CLIENTCRAP, buf->str);
	}
	g_string_free(buf, TRUE);

	g_io_channel_unref(handle);
	return TRUE;
}

static void show_help(const char *data)
{
	COMMAND_REC *rec, *last;
	GSList *tmp, *cmdlist;
	int items, findlen;
	int header, found, fullmatch;

	g_return_if_fail(data != NULL);

	/* sort the commands list */
	commands = g_slist_sort(commands, (GCompareFunc) commands_equal);

	/* print command, sort by category */
	cmdlist = NULL; last = NULL; header = FALSE; fullmatch = FALSE;
	items = 0; findlen = strlen(data); found = FALSE;
	for (tmp = commands; tmp != NULL; last = rec, tmp = tmp->next) {
		rec = tmp->data;

		if (last != NULL && rec->category != NULL &&
		    (last->category == NULL ||
		     g_strcmp0(rec->category, last->category) != 0)) {
			/* category changed */
			if (items > 0) {
				if (!header) {
					printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "Irssi commands:");
					header = TRUE;
				}
				if (last->category != NULL) {
					printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "");
					printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s:", last->category);
				}
				help_category(cmdlist, items);
			}

			g_slist_free(cmdlist); cmdlist = NULL;
			items = 0;
		}

		if (last != NULL && g_ascii_strcasecmp(rec->cmd, last->cmd) == 0)
			continue; /* don't display same command twice */

		if ((int)strlen(rec->cmd) >= findlen &&
		    g_ascii_strncasecmp(rec->cmd, data, findlen) == 0) {
			if (rec->cmd[findlen] == '\0') {
				fullmatch = TRUE;
				found = TRUE;
				break;
			}
			else if (strchr(rec->cmd+findlen+1, ' ') == NULL) {
				/* not a subcommand (and matches the query) */
				items++;
				cmdlist = g_slist_append(cmdlist, rec);
				found = TRUE;
			}
		}
	}

	if ((!found || fullmatch) && !show_help_file(data)) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			  "No help for %s", data);
	}

	if (*data != '\0' && data[strlen(data)-1] != ' ' &&
	    command_have_sub(data)) {
		char *cmd;

		cmd = g_strconcat(data, " ", NULL);
		show_help(cmd);
		g_free(cmd);
	}

	if (items != 0) {
		/* display the last category */
		if (!header) {
			printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
				  "Irssi commands:");
			header = TRUE;
		}

		if (last->category != NULL) {
			printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "");
			printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
				  "%s:", last->category);
		}
		help_category(cmdlist, items);
		g_slist_free(cmdlist);
	}
}

/* SYNTAX: HELP [<command>] */
static void cmd_help(const char *data)
{
	char *cmd;

	cmd = g_ascii_strdown(data, -1);
	g_strchomp(cmd);
	show_help(cmd);
        g_free(cmd);
}

void fe_help_init(void)
{
        settings_add_str("misc", "help_path", HELPDIR);
	command_bind("help", NULL, (SIGNAL_FUNC) cmd_help);
}

void fe_help_deinit(void)
{
	command_unbind("help", (SIGNAL_FUNC) cmd_help);
}
