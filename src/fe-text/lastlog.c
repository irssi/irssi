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

static char *gui_window_line2text(LINE_REC *line, int coloring)
{
	GString *str;
	int color;
	char *ret, *ptr, *tmp;

	g_return_val_if_fail(line != NULL, NULL);

	str = g_string_new(NULL);

	color = 0;
	for (ptr = line->text; ; ptr++) {
		if (*ptr != 0) {
			g_string_append_c(str, *ptr);
			continue;
		}

		ptr++;
		if (!coloring) {
			/* no colors, handle only commands that don't
			   have anything to do with colors */
			switch ((unsigned char) *ptr) {
			case LINE_CMD_EOL:
			case LINE_CMD_FORMAT:
				ret = str->str;
				g_string_free(str, FALSE);
				return ret;
			case LINE_CMD_CONTINUE:
				memcpy(&tmp, ptr+1, sizeof(char *));
				ptr = tmp-1;
				break;
			}
                        continue;
		}

		if ((*ptr & 0x80) == 0) {
			/* set color */
			color = *ptr;
			g_string_sprintfa(str, "\004%c%c", (color & 0x0f)+'0',
					  ((color & 0xf0) >> 4)+'0');
		}
		else switch ((unsigned char) *ptr)
		{
		case LINE_CMD_EOL:
		case LINE_CMD_FORMAT:
			ret = str->str;
			g_string_free(str, FALSE);
			return ret;
		case LINE_CMD_CONTINUE:
			memcpy(&tmp, ptr+1, sizeof(char *));
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

static void show_lastlog(const char *searchtext, GHashTable *optlist,
			 int start, int count)
{
        WINDOW_REC *window;
	GList *startline, *list, *tmp;
	char *str, *line;
	int level, fhandle;

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

	list = gui_window_find_text(window, searchtext, startline,
				    g_hash_table_lookup(optlist, "regexp") != NULL,
				    g_hash_table_lookup(optlist, "word") != NULL);
	tmp = lastlog_find_startline(list, count, start, level);

	for (; tmp != NULL && (count < 0 || count > 0); tmp = tmp->next) {
		LINE_REC *rec = tmp->data;

		if (!lastlog_match(rec, level))
			continue;
		count--;

                /* get the line text */
		line = gui_window_line2text(rec, fhandle == -1);
		if (settings_get_bool("timestamps"))
                        str = line;
		else {
			struct tm *tm = localtime(&rec->time);
			str = g_strdup_printf("%02d:%02d %s",
					      tm->tm_hour, tm->tm_min, line);
		}

                /* write to file/window */
		if (fhandle != -1) {
			write(fhandle, line, strlen(line));
			write(fhandle, "\n", 1);
		} else {
			printtext_window(active_win, MSGLEVEL_LASTLOG,
					 "%s", line);
		}

		if (str != line) g_free(str);
		g_free(line);
	}

	if (fhandle == -1 && g_hash_table_lookup(optlist, "-") == NULL)
		printformat(NULL, NULL, MSGLEVEL_LASTLOG, TXT_LASTLOG_END);

	if (fhandle != -1)
                close(fhandle);

	WINDOW_GUI(window)->lastlog_last_check =
		g_list_last(WINDOW_GUI(window)->bottom_startline);

	g_list_free(list);
}

/* SYNTAX: LASTLOG [-] [-file <filename>] [-clear] [-<level> -<level...>]
		   [-new | -away] [-regexp | -word] [-window <ref#|name>]
		   [<pattern>] [<count> [<start>]] */
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

	command_set_options("lastlog", "!- clear -file -window new away word regexp");
}

void lastlog_deinit(void)
{
	command_unbind("lastlog", (SIGNAL_FUNC) cmd_lastlog);
}
