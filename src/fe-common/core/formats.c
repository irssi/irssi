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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "special-vars.h"
#include "settings.h"

#include "levels.h"
#include "servers.h"

#include "fe-windows.h"
#include "window-items.h"
#include "formats.h"
#include "themes.h"
#include "recode.h"
#include "utf8.h"

static const char *format_backs = "04261537";
static const char *format_fores = "kbgcrmyw";
static const char *format_boldfores = "KBGCRMYW";

static int signal_gui_print_text;
static int hide_text_style, hide_server_tags, hide_colors;

static int timestamp_level;
static int timestamp_timeout;

int format_find_tag(const char *module, const char *tag)
{
	FORMAT_REC *formats;
	int n;

	formats = g_hash_table_lookup(default_formats, module);
	if (formats == NULL)
		return -1;

	for (n = 0; formats[n].def != NULL; n++) {
		if (formats[n].tag != NULL &&
		    g_strcasecmp(formats[n].tag, tag) == 0)
			return n;
	}

	return -1;
}

static void format_expand_code(const char **format, GString *out, int *flags)
{
	int set;

	if (flags == NULL) {
		/* flags are being ignored - skip the code */
		while (**format != ']')
			(*format)++;
		return;
	}

	set = TRUE;
	(*format)++;
	while (**format != ']' && **format != '\0') {
		if (**format == '+')
			set = TRUE;
		else if (**format == '-')
			set = FALSE;
		else switch (**format) {
		case 's':
		case 'S':
			*flags |= !set ? PRINT_FLAG_UNSET_LINE_START :
				**format == 's' ? PRINT_FLAG_SET_LINE_START :
				PRINT_FLAG_SET_LINE_START_IRSSI;
			break;
		case 't':
			*flags |= set ? PRINT_FLAG_SET_TIMESTAMP :
				PRINT_FLAG_UNSET_TIMESTAMP;
			break;
		case 'T':
			*flags |= set ? PRINT_FLAG_SET_SERVERTAG :
				PRINT_FLAG_UNSET_SERVERTAG;
			break;
		}

		(*format)++;
	}
}

int format_expand_styles(GString *out, const char **format, int *flags)
{
	char *p, fmt;

	fmt = **format;
	switch (fmt) {
	case '{':
	case '}':
	case '%':
		/* escaped char */
		g_string_append_c(out, fmt);
		break;
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
		/* blink */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_BLINK);
		break;
	case 'n':
	case 'N':
		/* default color */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_DEFAULTS);
		break;
	case '>':
		/* clear to end of line */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_CLRTOEOL);
		break;
	case '#':
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_MONOSPACE);
		break;
	case '[':
		/* code */
		format_expand_code(format, out, flags);
		break;
	default:
		/* check if it's a background color */
		p = strchr(format_backs, fmt);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			g_string_append_c(out, (char) ((int) (p-format_backs)+'0'));
			break;
		}

		/* check if it's a foreground color */
		if (fmt == 'p') fmt = 'm';
		p = strchr(format_fores, fmt);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, (char) ((int) (p-format_fores)+'0'));
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			break;
		}

		/* check if it's a bold foreground color */
		if (fmt == 'P') fmt = 'M';
		p = strchr(format_boldfores, fmt);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, (char) (8+(int) (p-format_boldfores)+'0'));
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			break;
		}

		return FALSE;
	}

	return TRUE;
}

void format_read_arglist(va_list va, FORMAT_REC *format,
			 char **arglist, int arglist_size,
			 char *buffer, int buffer_size)
{
	int num, len, bufpos;

	g_return_if_fail(format->params < arglist_size);

	bufpos = 0;
	arglist[format->params] = NULL;
	for (num = 0; num < format->params; num++) {
		switch (format->paramtypes[num]) {
		case FORMAT_STRING:
			arglist[num] = (char *) va_arg(va, char *);
			if (arglist[num] == NULL)
				arglist[num] = "";
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
	format_create_dest_tag(dest, server, NULL, target, level, window);
}

void format_create_dest_tag(TEXT_DEST_REC *dest, void *server,
			    const char *server_tag, const char *target,
			    int level, WINDOW_REC *window)
{
	memset(dest, 0, sizeof(TEXT_DEST_REC));

	dest->server = server;
	dest->server_tag = server != NULL ? SERVER(server)->tag : server_tag;
	dest->target = target;
	dest->level = level;
	dest->window = window != NULL ? window :
		window_find_closest(server, target, level);
}

static int advance (char const **str, gboolean utf8)
{
	if (utf8) {
		gunichar c;

		c = g_utf8_get_char(*str);
		*str = g_utf8_next_char(*str);

		return unichar_isprint(c) ? mk_wcwidth(c) : 1;
	} else {
		*str += 1;

		return 1;
	}
}

/* Return length of text part in string (ie. without % codes) */
int format_get_length(const char *str)
{
	GString *tmp;
	int len;
	gboolean utf8;

	g_return_val_if_fail(str != NULL, 0);

	utf8 = is_utf8() && g_utf8_validate(str, -1, NULL);

	tmp = g_string_new(NULL);
	len = 0;
	while (*str != '\0') {
		if (*str == '%' && str[1] != '\0') {
			str++;
			if (*str != '%' &&
			    format_expand_styles(tmp, &str, NULL)) {
				str++;
				continue;
			}

			/* %% or unknown %code, written as-is */
			if (*str != '%')
				len++;
		}

		len += advance(&str, utf8);
	}

	g_string_free(tmp, TRUE);
	return len;
}

/* Return how many characters in `str' must be skipped before `len'
   characters of text is skipped. Like strip_real_length(), except this
   handles %codes. */
int format_real_length(const char *str, int len)
{
	GString *tmp;
	const char *start;
	const char *oldstr;
	gboolean utf8;

	g_return_val_if_fail(str != NULL, 0);
	g_return_val_if_fail(len >= 0, 0);

	utf8 = is_utf8() && g_utf8_validate(str, -1, NULL);

	start = str;
	tmp = g_string_new(NULL);
	while (*str != '\0' && len > 0) {
		if (*str == '%' && str[1] != '\0') {
			str++;
			if (*str != '%' &&
			    format_expand_styles(tmp, &str, NULL)) {
				str++;
				continue;
			}

			/* %% or unknown %code, written as-is */
			if (*str != '%') {
				if (--len == 0)
					break;
			}
		}

		oldstr = str;
		len -= advance(&str, utf8);
		if (len < 0)
			str = oldstr;
	}

	g_string_free(tmp, TRUE);
	return (int) (str-start);
}

char *format_string_expand(const char *text, int *flags)
{
	GString *out;
	char code, *ret;

	g_return_val_if_fail(text != NULL, NULL);

	out = g_string_new(NULL);

	if (flags != NULL) *flags = 0;
	code = 0;
	while (*text != '\0') {
		if (code == '%') {
			/* color code */
			if (!format_expand_styles(out, &text, flags)) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *text);
			}
			code = 0;
		} else {
			if (*text == '%')
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

static char *format_get_text_args(TEXT_DEST_REC *dest,
				  const char *text, char **arglist)
{
	GString *out;
	char code, *ret;
	int need_free;

	out = g_string_new(NULL);

	code = 0;
	while (*text != '\0') {
		if (code == '%') {
			/* color code */
			if (!format_expand_styles(out, &text, &dest->flags)) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *text);
			}
			code = 0;
		} else if (code == '$') {
			/* argument */
			char *ret;

			ret = parse_special((char **) &text, dest->server,
					    dest->target == NULL ? NULL :
					    window_item_find(dest->server, dest->target),
					    arglist, &need_free, NULL, 0);

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

	if (theme == NULL)
		theme = window_get_theme(dest->window);

	va_start(va, formatnum);
	str = format_get_text_theme_args(theme, module, dest, formatnum, va);
	va_end(va);

	return str;
}

char *format_get_text_theme_args(THEME_REC *theme, const char *module,
				 TEXT_DEST_REC *dest, int formatnum,
				 va_list va)
{
	char *arglist[MAX_FORMAT_PARAMS];
	char buffer[DEFAULT_FORMAT_ARGLIST_SIZE];
	FORMAT_REC *formats;

	formats = g_hash_table_lookup(default_formats, module);
	format_read_arglist(va, &formats[formatnum],
			    arglist, sizeof(arglist)/sizeof(char *),
			    buffer, sizeof(buffer));

	return format_get_text_theme_charargs(theme, module, dest,
					      formatnum, arglist);
}

char *format_get_text_theme_charargs(THEME_REC *theme, const char *module,
				     TEXT_DEST_REC *dest, int formatnum,
				     char **args)
{
	MODULE_THEME_REC *module_theme;
	char *text;

	module_theme = g_hash_table_lookup(theme->modules, module);
	if (module_theme == NULL)
		return NULL;

	text = module_theme->expanded_formats[formatnum];
	return format_get_text_args(dest, text, args);
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
	theme = window_get_theme(dest.window);

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

char *format_add_lineend(const char *text, const char *linestart)
{
	GString *str;
	char *ret;

	if (linestart == NULL)
		return g_strdup(text);

	if (strchr(text, '\n') == NULL)
		return g_strconcat(text, linestart, NULL);

	str = g_string_new(NULL);
	while (*text != '\0') {
		if (*text == '\n')
			g_string_append(str, linestart);
		g_string_append_c(str, *text);
		text++;
	}
	g_string_append(str, linestart);

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
char *format_get_level_tag(THEME_REC *theme, TEXT_DEST_REC *dest)
{
	int format;

	/* check for flags if we want to override defaults */
	if (dest->flags & PRINT_FLAG_UNSET_LINE_START)
		return NULL;

	if (dest->flags & PRINT_FLAG_SET_LINE_START)
		format = TXT_LINE_START;
	else if (dest->flags & PRINT_FLAG_SET_LINE_START_IRSSI)
		format = TXT_LINE_START_IRSSI;
	else {
		/* use defaults */
		if (dest->level & LINE_START_IRSSI_LEVEL)
			format = TXT_LINE_START_IRSSI;
		else if ((dest->level & NOT_LINE_START_LEVEL) == 0)
			format = TXT_LINE_START;
		else
			return NULL;
	}

	return format_get_text_theme(theme, MODULE_NAME, dest, format);
}

static char *get_timestamp(THEME_REC *theme, TEXT_DEST_REC *dest, time_t t)
{
	char *format, str[256];
	struct tm *tm;
	int diff;

	if ((timestamp_level & dest->level) == 0)
		return NULL;

	/* check for flags if we want to override defaults */
	if (dest->flags & PRINT_FLAG_UNSET_TIMESTAMP)
		return NULL;

	if ((dest->flags & PRINT_FLAG_SET_TIMESTAMP) == 0 &&
	    (dest->level & (MSGLEVEL_NEVER|MSGLEVEL_LASTLOG)) != 0)
		return NULL;


	if (timestamp_timeout > 0) {
		diff = t - dest->window->last_timestamp;
		dest->window->last_timestamp = t;
		if (diff < timestamp_timeout)
			return NULL;
	}

	tm = localtime(&t);
	format = format_get_text_theme(theme, MODULE_NAME, dest,
				       TXT_TIMESTAMP);
	if (strftime(str, sizeof(str), format, tm) <= 0)
		str[0] = '\0';
	g_free(format);
	return g_strdup(str);
}

static char *get_server_tag(THEME_REC *theme, TEXT_DEST_REC *dest)
{
	int count = 0;

	if (dest->server_tag == NULL || hide_server_tags)
		return NULL;

	/* check for flags if we want to override defaults */
	if (dest->flags & PRINT_FLAG_UNSET_SERVERTAG)
		return NULL;

	if ((dest->flags & PRINT_FLAG_SET_SERVERTAG) == 0) {
		if (dest->window->active != NULL &&
		    dest->window->active->server == dest->server)
			return NULL;

		if (servers != NULL) {
			count++;
			if (servers->next != NULL)
				count++;
		}
		if (count < 2 && lookup_servers != NULL) {
			count++;
			if (lookup_servers->next != NULL)
				count++;
		}

		if (count < 2)
			return NULL;
	}

	return format_get_text_theme(theme, MODULE_NAME, dest,
				     TXT_SERVERTAG, dest->server_tag);
}

char *format_get_line_start(THEME_REC *theme, TEXT_DEST_REC *dest, time_t t)
{
	char *timestamp, *servertag;
	char *linestart;

	timestamp = get_timestamp(theme, dest, t);
	servertag = get_server_tag(theme, dest);

	if (timestamp == NULL && servertag == NULL)
		return NULL;

	linestart = g_strconcat(timestamp != NULL ? timestamp : "",
				servertag, NULL);

	g_free_not_null(timestamp);
	g_free_not_null(servertag);
	return linestart;
}

void format_newline(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	signal_emit_id(signal_gui_print_text, 6, window,
		       GINT_TO_POINTER(-1), GINT_TO_POINTER(-1),
		       GINT_TO_POINTER(GUI_PRINT_FLAG_NEWLINE),
		       "", NULL);
}

/* parse ANSI color string */
static const char *get_ansi_color(THEME_REC *theme, const char *str,
				  int *fg_ret, int *bg_ret, int *flags_ret)
{
	static char ansitab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	const char *start;
	int fg, bg, flags, num;

	if (*str != '[')
		return str;
	start = str++;

	fg = fg_ret == NULL || *fg_ret < 0 ? theme->default_color : *fg_ret;
	bg = bg_ret == NULL || *bg_ret < 0 ? -1 : *bg_ret;
	flags = flags_ret == NULL ? 0 : *flags_ret;

	num = 0;
	for (;; str++) {
		if (*str == '\0') return start;

		if (i_isdigit(*str)) {
			num = num*10 + (*str-'0');
			continue;
		}

		if (*str != ';' && *str != 'm')
			return start;

		switch (num) {
		case 0:
			/* reset colors back to default */
			fg = theme->default_color;
			bg = -1;
			flags &= ~GUI_PRINT_FLAG_INDENT;
			break;
		case 1:
			/* hilight */
			flags |= GUI_PRINT_FLAG_BOLD;
			break;
		case 5:
			/* blink */
			flags |= GUI_PRINT_FLAG_BLINK;
			break;
		case 7:
			/* reverse */
			flags |= GUI_PRINT_FLAG_REVERSE;
			break;
		default:
			if (num >= 30 && num <= 37) {
				if (fg == -1) fg = 0;
				fg = (fg & 0xf8) | ansitab[num-30];
			}
			if (num >= 40 && num <= 47) {
				if (bg == -1) bg = 0;
				bg = (bg & 0xf8) | ansitab[num-40];
			}
			break;
		}
		num = 0;

		if (*str == 'm') {
			if (fg_ret != NULL) *fg_ret = fg;
			if (bg_ret != NULL) *bg_ret = bg;
			if (flags_ret != NULL) *flags_ret = flags;

			str++;
			break;
		}
	}

	return str;
}

/* parse MIRC color string */
static void get_mirc_color(const char **str, int *fg_ret, int *bg_ret)
{
	int fg, bg;

	fg = fg_ret == NULL ? -1 : *fg_ret;
	bg = bg_ret == NULL ? -1 : *bg_ret;

	if (!i_isdigit(**str) && **str != ',') {
		fg = -1;
		bg = -1;
	} else {
		/* foreground color */
		if (**str != ',') {
			fg = **str-'0';
			(*str)++;
			if (i_isdigit(**str)) {
				fg = fg*10 + (**str-'0');
				(*str)++;
			}
		}
		if (**str == ',') {
			/* background color */
			if (!i_isdigit((*str)[1]))
				bg = -1;
			else {
				(*str)++;
				bg = **str-'0';
				(*str)++;
				if (i_isdigit(**str)) {
					bg = bg*10 + (**str-'0');
					(*str)++;
				}
			}
		}
	}

	if (fg_ret) *fg_ret = fg;
	if (bg_ret) *bg_ret = bg;
}

#define IS_COLOR_CODE(c) \
	((c) == 2 || (c) == 3 || (c) == 4 || (c) == 6 || (c) == 7 || \
	(c) == 15 || (c) == 22 || (c) == 27 || (c) == 31)

/* Return how many characters in `str' must be skipped before `len'
   characters of text is skipped. */
int strip_real_length(const char *str, int len,
		      int *last_color_pos, int *last_color_len)
{
	const char *start = str;

	if (last_color_pos != NULL)
		*last_color_pos = -1;
	if (last_color_len != NULL)
		*last_color_len = -1;

	while (*str != '\0') {
		if (*str == 3) {
			const char *mircstart = str;

			if (last_color_pos != NULL)
				*last_color_pos = (int) (str-start);
			str++;
			get_mirc_color(&str, NULL, NULL);
			if (last_color_len != NULL)
				*last_color_len = (int) (str-mircstart);

		} else if (*str == 4 && str[1] != '\0') {
			if (str[1] < FORMAT_STYLE_SPECIAL && str[2] != '\0') {
				if (last_color_pos != NULL)
					*last_color_pos = (int) (str-start);
				if (last_color_len != NULL)
					*last_color_len = 3;
				str++;
			} else if (str[1] == FORMAT_STYLE_DEFAULTS) {
				if (last_color_pos != NULL)
					*last_color_pos = (int) (str-start);
				if (last_color_len != NULL)
					*last_color_len = 2;
			}
			str += 2;
		} else {
			if (!IS_COLOR_CODE(*str)) {
				if (len-- == 0)
					break;
			}
			str++;
		}
	}

	return (int) (str-start);
}

char *strip_codes(const char *input)
{
	const char *p;
	char *str, *out;

	out = str = g_strdup(input);
	for (p = input; *p != '\0'; p++) {
		if (*p == 3) {
			p++;

			/* mirc color */
			get_mirc_color(&p, NULL, NULL);
			p--;
			continue;
		}

		if (*p == 4 && p[1] != '\0') {
			if (p[1] >= FORMAT_STYLE_SPECIAL) {
				p++;
				continue;
			}

			/* irssi color */
			if (p[2] != '\0') {
				p += 2;
				continue;
			}
		}

		if (*p == 27 && p[1] != '\0') {
			p++;
			p = get_ansi_color(current_theme, p, NULL, NULL, NULL);
			p--;
		} else if (!IS_COLOR_CODE(*p))
			*out++ = *p;
	}

	*out = '\0';
	return str;
}

/* send a fully parsed text string for GUI to print */
void format_send_to_gui(TEXT_DEST_REC *dest, const char *text)
{
	THEME_REC *theme;
	char *dup, *str, *ptr, type;
	int fgcolor, bgcolor;
	int flags;

	theme = window_get_theme(dest->window);

	dup = str = g_strdup(text);

	flags = 0; fgcolor = theme->default_color; bgcolor = -1;
	while (*str != '\0') {
		type = '\0';
		for (ptr = str; *ptr != '\0'; ptr++) {
			if (IS_COLOR_CODE(*ptr) || *ptr == '\n') {
				type = *ptr;
				*ptr++ = '\0';
				break;
			}
		}

		if (type == 7) {
			/* bell */
			if (settings_get_bool("bell_beeps"))
				signal_emit("beep", 0);
		} else if (type == 4 && *ptr == FORMAT_STYLE_CLRTOEOL) {
			/* clear to end of line */
			flags |= GUI_PRINT_FLAG_CLRTOEOL;
		}

		if (*str != '\0' || (flags & GUI_PRINT_FLAG_CLRTOEOL)) {
			/* send the text to gui handler */
			signal_emit_id(signal_gui_print_text, 6, dest->window,
				       GINT_TO_POINTER(fgcolor),
				       GINT_TO_POINTER(bgcolor),
				       GINT_TO_POINTER(flags), str,
				       dest);
			flags &= ~(GUI_PRINT_FLAG_INDENT|GUI_PRINT_FLAG_CLRTOEOL);
		}

		if (type == '\n') {
			format_newline(dest->window);
			fgcolor = theme->default_color;
			bgcolor = -1;
			flags &= GUI_PRINT_FLAG_INDENT|GUI_PRINT_FLAG_MONOSPACE;
		}

		if (*ptr == '\0')
			break;

		switch (type)
		{
		case 2:
			/* bold */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_BOLD;
			break;
		case 3:
			/* MIRC color */
			get_mirc_color((const char **) &ptr,
					hide_colors ? NULL : &fgcolor,
					hide_colors ? NULL : &bgcolor);
			if (!hide_colors)
				flags |= GUI_PRINT_FLAG_MIRC_COLOR;
			break;
		case 4:
			/* user specific colors */
			flags &= ~GUI_PRINT_FLAG_MIRC_COLOR;
			switch (*ptr) {
			case FORMAT_STYLE_BLINK:
				flags ^= GUI_PRINT_FLAG_BLINK;
				break;
			case FORMAT_STYLE_UNDERLINE:
				flags ^= GUI_PRINT_FLAG_UNDERLINE;
				break;
			case FORMAT_STYLE_BOLD:
				flags ^= GUI_PRINT_FLAG_BOLD;
				break;
			case FORMAT_STYLE_REVERSE:
				flags ^= GUI_PRINT_FLAG_REVERSE;
				break;
			case FORMAT_STYLE_MONOSPACE:
				flags ^= GUI_PRINT_FLAG_MONOSPACE;
				break;
			case FORMAT_STYLE_INDENT:
				flags |= GUI_PRINT_FLAG_INDENT;
				break;
			case FORMAT_STYLE_DEFAULTS:
				fgcolor = theme->default_color;
				bgcolor = -1;
				flags &= GUI_PRINT_FLAG_INDENT|GUI_PRINT_FLAG_MONOSPACE;
				break;
			case FORMAT_STYLE_CLRTOEOL:
				break;
			default:
				if (*ptr != FORMAT_COLOR_NOCHANGE) {
					fgcolor = (unsigned char) *ptr-'0';
				}
				if (ptr[1] == '\0')
					break;

				ptr++;
				if (*ptr != FORMAT_COLOR_NOCHANGE) {
					bgcolor = *ptr-'0';
				}
			}
			ptr++;
			break;
		case 6:
			/* blink */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_BLINK;
			break;
		case 15:
			/* remove all styling */
			fgcolor = theme->default_color;
			bgcolor = -1;
			flags &= GUI_PRINT_FLAG_INDENT|GUI_PRINT_FLAG_MONOSPACE;
			break;
		case 22:
			/* reverse */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_REVERSE;
			break;
		case 31:
			/* underline */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_UNDERLINE;
			break;
		case 27:
			/* ansi color code */
			ptr = (char *)
				get_ansi_color(theme, ptr,
					       hide_colors ? NULL : &fgcolor,
					       hide_colors ? NULL : &bgcolor,
					       hide_colors ? NULL : &flags);
			break;
		}

		str = ptr;
	}

	g_free(dup);
}

static void read_settings(void)
{
	timestamp_level = settings_get_bool("timestamps") ? MSGLEVEL_ALL : 0;
	if (timestamp_level > 0)
		timestamp_level = settings_get_level("timestamp_level");
	timestamp_timeout = settings_get_time("timestamp_timeout")/1000;

	hide_server_tags = settings_get_bool("hide_server_tags");
	hide_text_style = settings_get_bool("hide_text_style");
	hide_colors = hide_text_style || settings_get_bool("hide_colors");
}

void formats_init(void)
{
	signal_gui_print_text = signal_get_uniq_id("gui print text");

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void formats_deinit(void)
{
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
