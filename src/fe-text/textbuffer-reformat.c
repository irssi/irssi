/*
 textbuffer-reformat.c : Reformatting lines in text buffer

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
#include "settings.h"

#include "formats.h"

#include "gui-windows.h"
#include "gui-printtext.h"
#include "textbuffer.h"

static GString *format;
static int scrollback_save_formats;

/* Read one block between \0<format>s */
static char *line_read_format(unsigned const char **text)
{
	GString *str;
	char *ret;

	str = g_string_new(NULL);
	for (;;) {
		if (**text == '\0') {
			if ((*text)[1] == LINE_CMD_EOL) {
				/* leave text at \0<eof> */
				break;
			}
			if ((*text)[1] == LINE_CMD_FORMAT_CONT) {
				/* leave text at \0<format_cont> */
				break;
			}
			(*text)++;

			 if (**text == LINE_CMD_FORMAT) {
				/* move text to start after \0<format> */
				(*text)++;
				break;
			}

			if (**text == LINE_CMD_CONTINUE) {
				unsigned char *tmp;

				memcpy(&tmp, (*text)+1, sizeof(char *));
				*text = tmp;
				continue;
			} else if (**text & 0x80)
				(*text)++;
			continue;
		}

		g_string_append_c(str, (char) **text);
		(*text)++;
	}

	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

static char *textbuffer_line_get_format(WINDOW_REC *window, LINE_REC *line,
					GString *raw)
{
	const unsigned char *text;
	char *module, *format_name, *args[MAX_FORMAT_PARAMS], *ret;
	TEXT_DEST_REC dest;
	int formatnum, argcount;

	text = (const unsigned char *) line->text;

	/* skip the beginning of the line until we find the format */
	format_name = line_read_format(&text);
	g_free(format_name);
	if (text[1] == LINE_CMD_FORMAT_CONT) {
		if (raw != NULL) {
			g_string_append_c(raw, '\0');
			g_string_append_c(raw, (char)LINE_CMD_FORMAT_CONT);
		}
		return NULL;
	}

	/* read format information */
        module = line_read_format(&text);
	format_name = line_read_format(&text);

	if (raw != NULL) {
		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_FORMAT);

		g_string_append(raw, module);

		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_FORMAT);

		g_string_append(raw, format_name);
	}

	formatnum = format_find_tag(module, format_name);
	if (formatnum == -1)
		ret = NULL;
	else {
                argcount = 0;
                memset(args, 0, sizeof(args));
		while (*text != '\0' || text[1] != LINE_CMD_EOL) {
			args[argcount] = line_read_format(&text);
			if (raw != NULL) {
				g_string_append_c(raw, '\0');
				g_string_append_c(raw,
						  (char)LINE_CMD_FORMAT);

				g_string_append(raw, args[argcount]);
			}
			argcount++;
		}

		/* get the format text */
		format_create_dest(&dest, NULL, NULL, line->info.level, window);
		ret = format_get_text_theme_charargs(current_theme,
						     module, &dest,
						     formatnum, args);
		while (argcount > 0)
			g_free(args[--argcount]);
	}

	g_free(module);
	g_free(format_name);

	return ret;
}

void textbuffer_reformat_line(WINDOW_REC *window, LINE_REC *line)
{
        GUI_WINDOW_REC *gui;
	TEXT_DEST_REC dest;
	LINE_REC *line_prev;
        LINE_INFO_REC line_info;
	GString *raw;
	char *str, *tmp, *prestr, *linestart, *leveltag;

        gui = WINDOW_GUI(window);

	raw = g_string_new(NULL);
	str = textbuffer_line_get_format(window, line, raw);

        if (str == NULL && raw->len == 2 &&
            raw->str[1] == (char)LINE_CMD_FORMAT_CONT) {
                /* multiline format, format explained in one the
                   following lines. remove this line. */
                textbuffer_view_remove_line(gui->view, line);
	} else if (str != NULL) {
                /* FIXME: ugly ugly .. and this can't handle
                   unformatted lines.. */
		g_string_append_c(raw, '\0');
		g_string_append_c(raw, (char)LINE_CMD_EOL);

		line_prev = line->prev;
                memcpy(&line_info, &line->info, sizeof(line_info));
                textbuffer_view_remove_line(gui->view, line); line = NULL;

		format_create_dest(&dest, NULL, NULL, line_info.level, window);

		linestart = format_get_line_start(current_theme, &dest, line_info.time);
		leveltag = format_get_level_tag(current_theme, &dest);

		prestr = g_strconcat(linestart == NULL ? "" : linestart,
				     leveltag, NULL);
		g_free_not_null(linestart);
		g_free_not_null(leveltag);

		tmp = format_add_linestart(str, prestr);
		g_free(str);
		g_free(prestr);

                gui_printtext_after(&dest, line_prev, tmp);
		g_free(tmp);

                line = textbuffer_insert(gui->view->buffer, gui->insert_after,
					 (unsigned char *) raw->str,
					 raw->len, &line_info);
		textbuffer_view_insert_line(gui->view, line);
	}
	g_string_free(raw, TRUE);
}

static void sig_print_format(THEME_REC *theme, const char *module,
			     TEXT_DEST_REC *dest, void *formatnump,
			     char **args)
{
	FORMAT_REC *formats;
	int formatnum, n;

	if (!scrollback_save_formats)
		return;

	formatnum = GPOINTER_TO_INT(formatnump);
	formats = g_hash_table_lookup(default_formats, module);

	/* <module><format_name><arg...> */
	g_string_truncate(format, 0);

	g_string_append_c(format, '\0');
	g_string_append_c(format, (char)LINE_CMD_FORMAT);

        g_string_append(format, module);

	g_string_append_c(format, '\0');
	g_string_append_c(format, (char)LINE_CMD_FORMAT);

	g_string_append(format, formats[formatnum].tag);

	for (n = 0; n < formats[formatnum].params; n++) {
		g_string_append_c(format, '\0');
		g_string_append_c(format, (char)LINE_CMD_FORMAT);

		if (args[n] != NULL)
			g_string_append(format, args[n]);
	}
}

static void sig_gui_printtext_finished(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
        LINE_REC *insert_after;

	if (format->len == 0)
                return;

	/* save format of the line */
        gui = WINDOW_GUI(window);
	insert_after = gui->use_insert_after ?
		gui->insert_after : gui->view->buffer->cur_line;

	textbuffer_insert(gui->view->buffer, insert_after,
			  (unsigned char *) format->str,
			  format->len, NULL);

	g_string_truncate(format, 0);
}

static void read_settings(void)
{
        scrollback_save_formats = settings_get_bool("scrollback_save_formats");
}

void textbuffer_reformat_init(void)
{
	format = g_string_new(NULL);
	settings_add_bool("history", "scrollback_save_formats", FALSE);

        read_settings();
	signal_add("print format", (SIGNAL_FUNC) sig_print_format);
	signal_add_first("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void textbuffer_reformat_deinit(void)
{
	g_string_free(format, TRUE);

	signal_remove("print format", (SIGNAL_FUNC) sig_print_format);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
