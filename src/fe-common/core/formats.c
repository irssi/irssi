/*
 formats.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "special-vars.h"

#include "levels.h"

#include "windows.h"
#include "formats.h"
#include "themes.h"

int format_expand_styles(GString *out, char format, TEXT_DEST_REC *dest)
{
	static const char *backs = "04261537";
	static const char *fores = "kbgcrmyw";
	static const char *boldfores = "KBGCRMYW";
	char *p;

	switch (format) {
	case 'U':
		/* Underline on/off */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_UNDERLINE);
		break;
	case '9':
	case '_':
		/* bold on/off */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_BOLD);
		break;
	case '8':
		/* reverse */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_REVERSE);
		break;
	case '%':
		g_string_append_c(out, '%');
		break;
	case ':':
		/* Newline */
		g_string_append_c(out, '\n');
		break;
	case '|':
		/* Indent here */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_INDENT);
		break;
	case 'F':
		/* flashing - ignore */
		break;
	case 'N':
		/* don't put clear-color tag at the end of the output - ignore */
		break;
	case 'n':
		/* default color */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_DEFAULTS);
		break;
	default:
		/* check if it's a background color */
		p = strchr(backs, format);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			g_string_append_c(out, (int) (p-backs)+'0');
			break;
		}

		/* check if it's a foreground color */
		if (format == 'p') format = 'm';
		p = strchr(fores, format);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, (int) (p-fores)+'0');
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			break;
		}

		/* check if it's a bold foreground color */
		if (format == 'P') format = 'M';
		p = strchr(boldfores, format);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, 8+(int) (p-boldfores)+'0');
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			break;
		}

		return FALSE;
	}

	return TRUE;
}

static void read_arglist(va_list va, FORMAT_REC *format,
			 char **arglist, int arglist_size,
			 char *buffer, int buffer_size)
{
	int num, len, bufpos;

	bufpos = 0;
        arglist[format->params] = NULL;
	for (num = 0; num < format->params && num < arglist_size; num++) {
		switch (format->paramtypes[num]) {
		case FORMAT_STRING:
			arglist[num] = (char *) va_arg(va, char *);
			if (arglist[num] == NULL) {
				g_warning("read_arglist() : parameter %d is NULL", num);
				arglist[num] = "";
			}
			break;
		case FORMAT_INT: {
			int d = (int) va_arg(va, int);

			if (bufpos >= buffer_size) {
				arglist[num] = "";
				break;
			}

			arglist[num] = buffer+bufpos;
			len = g_snprintf(buffer+bufpos, buffer_size-bufpos,
					 "%d", d);
			bufpos += len+1;
			break;
		}
		case FORMAT_LONG: {
			long l = (long) va_arg(va, long);

			if (bufpos >= buffer_size) {
				arglist[num] = "";
				break;
			}

			arglist[num] = buffer+bufpos;
			len = g_snprintf(buffer+bufpos, buffer_size-bufpos,
					 "%ld", l);
                        bufpos += len+1;
			break;
		}
		case FORMAT_FLOAT: {
			double f = (double) va_arg(va, double);

			if (bufpos >= buffer_size) {
				arglist[num] = "";
				break;
			}

			arglist[num] = buffer+bufpos;
			len = g_snprintf(buffer+bufpos, buffer_size-bufpos,
					 "%0.2f", f);
			bufpos += len+1;
			break;
		}
		}
	}
}

void format_create_dest(TEXT_DEST_REC *dest,
			void *server, const char *target,
			int level, WINDOW_REC *window)
{
	dest->server = server;
	dest->target = target;
	dest->level = level;
	dest->window = window != NULL ? window :
		window_find_closest(server, target, level);
}

static char *format_get_text_args(TEXT_DEST_REC *dest, FORMAT_REC *format,
				  const char *text, va_list va)
{
	GString *out;
	char *arglist[10];
	char buffer[200]; /* should be enough? (won't overflow even if it isn't) */

	char code, *ret;
	int need_free;

	/* read all optional arguments to arglist[] list
	   so they can be used in any order.. */
	read_arglist(va, format,
		     arglist, sizeof(arglist)/sizeof(void*),
		     buffer, sizeof(buffer));

	out = g_string_new(NULL);

	code = 0;
	while (*text != '\0') {
		if (code == '%') {
			/* color code */
			if (!format_expand_styles(out, *text, dest)) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *text);
			}
			code = 0;
		} else if (code == '$') {
			/* argument */
			char *ret;

			ret = parse_special((char **) &text, active_win->active_server,
					    active_win->active, arglist, &need_free, NULL);

			if (ret != NULL) {
				/* string shouldn't end with \003 or it could
				   mess up the next one or two characters */
                                int diff;
				int len = strlen(ret);
				while (len > 0 && ret[len-1] == 3) len--;
				diff = strlen(ret)-len;

				g_string_append(out, ret);
				if (diff > 0)
					g_string_truncate(out, out->len-diff);
				if (need_free) g_free(ret);
			}
			code = 0;
		} else {
			if (*text == '%' || *text == '$')
				code = *text;
			else
				g_string_append_c(out, *text);
		}

		text++;
	}

	ret = out->str;
	g_string_free(out, FALSE);
	return ret;
}

char *format_get_text_theme(THEME_REC *theme, const char *module,
			    TEXT_DEST_REC *dest, int formatnum, ...)
{
	va_list va;
	char *str;

	if (theme == NULL) {
		theme = dest->window->theme == NULL ? current_theme :
			dest->window->theme;
	}

	va_start(va, formatnum);
	str = format_get_text_theme_args(theme, module, dest, formatnum, va);
	va_end(va);

	return str;
}

char *format_get_text_theme_args(THEME_REC *theme, const char *module,
				 TEXT_DEST_REC *dest, int formatnum,
				 va_list va)
{
	MODULE_THEME_REC *module_theme;
	FORMAT_REC *formats;
	char *str;

	module_theme = g_hash_table_lookup(theme->modules, module);
	formats = g_hash_table_lookup(default_formats, module);

	str = format_get_text_args(dest, &formats[formatnum],
				   module_theme->expanded_formats[formatnum], va);
	return str;
}

char *format_get_text(const char *module, WINDOW_REC *window,
		      void *server, const char *target,
		      int formatnum, ...)
{
	TEXT_DEST_REC dest;
	THEME_REC *theme;
	va_list va;
	char *str;

	format_create_dest(&dest, server, target, 0, window);
	theme = dest.window->theme == NULL ? current_theme :
		dest.window->theme;

	va_start(va, formatnum);
	str = format_get_text_theme_args(theme, module, &dest, formatnum, va);
	va_end(va);

	return str;
}

/* add `linestart' to start of each line in `text'. `text' may contain
   multiple lines separated with \n. */
char *format_add_linestart(const char *text, const char *linestart)
{
	GString *str;
	char *ret;

	if (linestart == NULL)
		return g_strdup(text);

	if (strchr(text, '\n') == NULL)
		return g_strconcat(linestart, text, NULL);

	str = g_string_new(linestart);
	while (*text != '\0') {
		g_string_append_c(str, *text);
		if (*text == '\n')
			g_string_append(str, linestart);
		text++;
	}

	ret = str->str;
	g_string_free(str, FALSE);
        return ret;
}

#define LINE_START_IRSSI_LEVEL \
	(MSGLEVEL_CLIENTERROR | MSGLEVEL_CLIENTNOTICE)

#define NOT_LINE_START_LEVEL \
	(MSGLEVEL_NEVER | MSGLEVEL_LASTLOG | MSGLEVEL_CLIENTCRAP | \
	MSGLEVEL_MSGS | MSGLEVEL_PUBLIC | MSGLEVEL_DCC | MSGLEVEL_DCCMSGS | \
	MSGLEVEL_ACTIONS | MSGLEVEL_NOTICES | MSGLEVEL_SNOTES | MSGLEVEL_CTCPS)

/* return the "-!- " text at the start of the line */
char *format_get_line_start(THEME_REC *theme, TEXT_DEST_REC *dest)
{
	int format;

	if (dest->level & LINE_START_IRSSI_LEVEL)
		format = IRCTXT_LINE_START_IRSSI;
	else if ((dest->level & NOT_LINE_START_LEVEL) == 0)
		format = IRCTXT_LINE_START;
	else
		return NULL;

	return format_get_text_theme(theme, MODULE_NAME, dest, format);
}
