/*
 printtext.c : irssi

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
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "special-vars.h"
#include "settings.h"

#include "levels.h"
#include "server.h"

#include "translation.h"
#include "themes.h"
#include "windows.h"

typedef struct {
	WINDOW_REC *window;
	void *server;
	const char *channel;
	int level;
} TEXT_DEST_REC;

static int timestamps, msgs_timestamps, hide_text_style;
static int timestamp_timeout;

static int signal_gui_print_text;
static int signal_print_text_stripped;
static int signal_print_text;
static int signal_print_text_finished;

static void print_string(TEXT_DEST_REC *dest, const char *text);

void printbeep(void)
{
	signal_emit_id(signal_gui_print_text, 6, active_win, NULL, NULL,
		       GINT_TO_POINTER(PRINTFLAG_BEEP), "", MSGLEVEL_NEVER);
}

static void skip_mirc_color(char **str)
{
	if (!isdigit((int) **str))
		return;

	/* foreground */
	(*str)++;
	if (isdigit((int) **str)) (*str)++;

	if (**str != ',' || !isdigit((int) (*str)[1])) return;

	/* background */
	(*str) += 2;
	if (isdigit((int) **str)) (*str)++;
}

#define is_color_code(c) \
	((c) == 2 || (c) == 3 || (c) == 4 || (c) == 6 || (c) == 7 || \
	(c) == 15 || (c) == 22 || (c) == 27 || (c) == 31)

char *strip_codes(const char *input)
{
	const char *p;
	char *str, *out;

	out = str = g_strdup(input);
	for (p = input; *p != '\0'; p++) {
		if (*p == 3) {
			p++;

			if (*p < 17 && *p > 0) {
				/* irssi color */
				if (p[1] < 17 && p[1] > 0) p++;
				continue;
			}

			/* mirc color */
			skip_mirc_color((char **) &p);
			p--;
			continue;
		}

		if (*p == 4 && p[1] != '\0' && p[2] != '\0') {
			/* irssi color */
			p += 2;
			continue;
		}

		if (!is_color_code(*p))
			*out++ = *p;
	}

	*out = '\0';
	return str;
}

/* parse ANSI color string */
static char *convert_ansi(char *str, int *fgcolor, int *bgcolor, int *flags)
{
	static char ansitab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	char *start;
	int fg, bg, fl, num;

	if (*str != '[')
		return str;
	start = str++;

	fg = *fgcolor < 0 ? current_theme->default_color : *fgcolor;
	bg = *bgcolor < 0 ? -1 : *bgcolor;
	fl = *flags;

	num = 0;
	for (;; str++) {
		if (*str == '\0') return start;

		if (isdigit((int) *str)) {
			num = num*10 + (*str-'0');
			continue;
		}

		if (*str != ';' && *str != 'm')
			return start;

		switch (num) {
		case 0:
			/* reset colors back to default */
			fg = current_theme->default_color;
			bg = -1;
			fl &= ~(PRINTFLAG_BEEP|PRINTFLAG_INDENT);
			break;
		case 1:
			/* hilight */
			fl |= PRINTFLAG_BOLD;
			break;
		case 5:
			/* blink */
			fl |= PRINTFLAG_BLINK;
			break;
		case 7:
			/* reverse */
			fl |= PRINTFLAG_REVERSE;
			break;
		default:
			if (num >= 30 && num <= 37)
				fg = (fg & 0xf8) + ansitab[num-30];
			if (num >= 40 && num <= 47) {
				if (bg == -1) bg = 0;
				bg = (bg & 0xf8) + ansitab[num-40];
			}
			break;
		}
		num = 0;

		if (*str == 'm') {
			if (!hide_text_style) {
				*fgcolor = fg;
				*bgcolor = bg;
				*flags = fl;
			}
			str++;
			break;
		}
	}

	return str;
}

static int expand_styles(GString *out, char format, TEXT_DEST_REC *dest)
{
	static const char *backs = "04261537";
	static const char *fores = "kbgcrmyw";
	static const char *boldfores = "KBGCRMYW";
	char *p;

	switch (format) {
	case 'U':
		/* Underline on/off */
		g_string_append_c(out, 4);
		g_string_append_c(out, -1);
		g_string_append_c(out, 2);
		break;
	case '9':
	case '_':
		/* bold on/off */
		g_string_append_c(out, 4);
		g_string_append_c(out, -1);
		g_string_append_c(out, 1);
		break;
	case '8':
		/* reverse */
		g_string_append_c(out, 4);
		g_string_append_c(out, -1);
		g_string_append_c(out, 3);
		break;
	case '%':
		g_string_append_c(out, '%');
		break;
	case ':':
		/* Newline */
		print_string(dest, out->str);
		g_string_truncate(out, 0);
		break;
	case '|':
		/* Indent here */
		g_string_append_c(out, 4);
		g_string_append_c(out, -1);
		g_string_append_c(out, 4);
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
		g_string_append_c(out, -1);
		g_string_append_c(out, -1);
		break;
	default:
		/* check if it's a background color */
		p = strchr(backs, format);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, -2);
			g_string_append_c(out, (int) (p-backs)+1);
			break;
		}

		/* check if it's a foreground color */
		if (format == 'p') format = 'm';
		p = strchr(fores, format);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, (int) (p-fores)+1);
			g_string_append_c(out, -2);
			break;
		}

		/* check if it's a bold foreground color */
		if (format == 'P') format = 'M';
		p = strchr(boldfores, format);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, 8+(int) (p-boldfores)+1);
			g_string_append_c(out, -2);
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

static char *output_format_text_args(TEXT_DEST_REC *dest, FORMAT_REC *format, const char *text, va_list args)
{
	GString *out;
	char *arglist[10];
	char buffer[200]; /* should be enough? (won't overflow even if it isn't) */

	const char *str;
	char code, *ret;
	int need_free;

	str = current_theme != NULL && text != NULL ? text : format->def;

	/* read all optional arguments to arglist[] list
	   so they can be used in any order.. */
	read_arglist(args, format,
		     arglist, sizeof(arglist)/sizeof(void*),
		     buffer, sizeof(buffer));

	out = g_string_new(NULL);

	code = 0;
	while (*str != '\0') {
		if (code == '%') {
			/* color code */
			if (!expand_styles(out, *str, dest)) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *str);
			}
			code = 0;
		} else if (code == '$') {
			/* argument */
			char *ret;

			ret = parse_special((char **) &str, active_win->active_server,
					    active_win->active, arglist, &need_free, NULL);
			if (ret != NULL) {
				g_string_append(out, ret);
				if (need_free) g_free(ret);
			}
			code = 0;
		} else {
			if (*str == '%' || *str == '$')
				code = *str;
			else
				g_string_append_c(out, *str);
		}

		str++;
	}

	ret = out->str;
	g_string_free(out, FALSE);
	return ret;
}

static char *output_format_text(TEXT_DEST_REC *dest, int formatnum, ...)
{
	MODULE_THEME_REC *theme;
	va_list args;
	char *ret;

	theme = g_hash_table_lookup(current_theme->modules, MODULE_NAME);

	va_start(args, formatnum);
	ret = output_format_text_args(dest, &fecommon_core_formats[formatnum],
				      theme == NULL ? NULL : theme->formats[formatnum], args);
	va_end(args);

	return ret;
}

void printformat_module_args(const char *module, void *server, const char *channel, int level, int formatnum, va_list va)
{
	MODULE_THEME_REC *theme;
	TEXT_DEST_REC dest;
	FORMAT_REC *formats;
	char *str;

	dest.window = NULL;
	dest.server = server;
	dest.channel = channel;
	dest.level = level;

	theme = g_hash_table_lookup(current_theme->modules, module);
	formats = g_hash_table_lookup(default_formats, module);

	str = output_format_text_args(&dest, &formats[formatnum],
				theme == NULL ? NULL : theme->formats[formatnum], va);
	if (*str != '\0') print_string(&dest, str);
	g_free(str);
}

void printformat_module(const char *module, void *server, const char *channel, int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_args(module, server, channel, level, formatnum, va);
	va_end(va);
}

void printformat_module_window_args(const char *module, WINDOW_REC *window, int level, int formatnum, va_list va)
{
	MODULE_THEME_REC *theme;
	TEXT_DEST_REC dest;
	FORMAT_REC *formats;
	char *str;

	dest.window = window;
	dest.server = NULL;
	dest.channel = NULL;
	dest.level = level;

	theme = g_hash_table_lookup(current_theme->modules, module);
	formats = g_hash_table_lookup(default_formats, module);

	str = output_format_text_args(&dest, &formats[formatnum],
				      theme == NULL ? NULL : theme->formats[formatnum], va);
	if (*str != '\0') print_string(&dest, str);
	g_free(str);
}

void printformat_module_window(const char *module, WINDOW_REC *window, int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_window_args(module, window, level, formatnum, va);
	va_end(va);
}

/* return the "-!- " text at the start of the line */
static char *get_line_start_text(TEXT_DEST_REC *dest)
{
	if ((dest->level & (MSGLEVEL_CLIENTERROR|MSGLEVEL_CLIENTNOTICE)) != 0)
		return output_format_text(dest, IRCTXT_LINE_START_IRSSI);

	if ((dest->level & (MSGLEVEL_MSGS|MSGLEVEL_PUBLIC|MSGLEVEL_NOTICES|MSGLEVEL_SNOTES|MSGLEVEL_CTCPS|MSGLEVEL_ACTIONS|MSGLEVEL_DCC|MSGLEVEL_CLIENTCRAP)) == 0 && dest->level != MSGLEVEL_NEVER)
		return output_format_text(dest, IRCTXT_LINE_START);

	return NULL;
}

static void print_string(TEXT_DEST_REC *dest, const char *text)
{
	gpointer levelp;
	char *str, *tmp;

	g_return_if_fail(dest != NULL);
	g_return_if_fail(text != NULL);

	if (dest->window == NULL)
		dest->window = window_find_closest(dest->server, dest->channel, dest->level);

	tmp = get_line_start_text(dest);
	str = tmp == NULL ? (char *) text :
		g_strconcat(tmp, text, NULL);
	g_free_not_null(tmp);

	levelp = GINT_TO_POINTER(dest->level);

	/* send the plain text version for logging etc.. */
	tmp = strip_codes(str);
	signal_emit_id(signal_print_text_stripped, 5, dest->window, dest->server, dest->channel, levelp, tmp);
	g_free(tmp);

	signal_emit_id(signal_print_text, 5, dest->window, dest->server, dest->channel, levelp, str);
	if (str != text) g_free(str);
}

/* append string to `out', expand newlines. */
static void printtext_append_str(TEXT_DEST_REC *dest, GString *out, const char *str)
{
	while (*str != '\0') {
		if (*str != '\n')
			g_string_append_c(out, *str);
		else {
			print_string(dest, out->str);
			g_string_truncate(out, 0);
		}
		str++;
	}
}

static char *printtext_get_args(TEXT_DEST_REC *dest, const char *str, va_list va)
{
	GString *out;
	char *ret;

	out = g_string_new(NULL);
	for (; *str != '\0'; str++) {
		if (*str != '%') {
			g_string_append_c(out, *str);
			continue;
		}

		if (*++str == '\0')
			break;

		/* standard parameters */
		switch (*str) {
		case 's': {
			char *s = (char *) va_arg(va, char *);
			if (s && *s) printtext_append_str(dest, out, s);
			break;
		}
		case 'd': {
			int d = (int) va_arg(va, int);
			g_string_sprintfa(out, "%d", d);
			break;
		}
		case 'f': {
			double f = (double) va_arg(va, double);
			g_string_sprintfa(out, "%0.2f", f);
			break;
		}
		case 'u': {
			unsigned int d = (unsigned int) va_arg(va, unsigned int);
			g_string_sprintfa(out, "%u", d);
			break;
                }
		case 'l': {
			long d = (long) va_arg(va, long);

			if (*++str != 'd' && *str != 'u') {
				g_string_sprintfa(out, "%ld", d);
				str--;
			} else {
				if (*str == 'd')
					g_string_sprintfa(out, "%ld", d);
				else
					g_string_sprintfa(out, "%lu", d);
			}
			break;
		}
		default:
			if (!expand_styles(out, *str, dest)) {
				g_string_append_c(out, '%');
				g_string_append_c(out, *str);
			}
			break;
		}
	}

	ret = out->str;
	g_string_free(out, FALSE);
	return ret;
}

/* Write text to channel - convert color codes */
void printtext(void *server, const char *channel, int level, const char *text, ...)
{
	TEXT_DEST_REC dest;
	char *str;
	va_list va;

	g_return_if_fail(text != NULL);

	dest.window = NULL;
	dest.server = server;
	dest.channel = channel;
	dest.level = level;

	va_start(va, text);
	str = printtext_get_args(&dest, text, va);
	va_end(va);

	print_string(&dest, str);
	g_free(str);
}

void printtext_window(WINDOW_REC *window, int level, const char *text, ...)
{
	TEXT_DEST_REC dest;
	char *str;
	va_list va;

	g_return_if_fail(text != NULL);

	dest.window = window != NULL ? window : active_win;
	dest.server = NULL;
	dest.channel = NULL;
	dest.level = level;

	va_start(va, text);
	str = printtext_get_args(&dest, text, va);
	va_end(va);

	print_string(&dest, str);
	g_free(str);
}

static void newline(WINDOW_REC *window)
{
	window->lines++;
	if (window->lines != 1) {
		signal_emit_id(signal_gui_print_text, 6, window,
			       GINT_TO_POINTER(-1), GINT_TO_POINTER(-1),
			       GINT_TO_POINTER(0), "\n", GINT_TO_POINTER(-1));
	}
}

#define show_timestamp(level) \
	((level) != MSGLEVEL_NEVER && \
	(timestamps || (msgs_timestamps && ((level) & MSGLEVEL_MSGS))))

static char *get_timestamp(TEXT_DEST_REC *dest)
{
	struct tm *tm;
	time_t t;
	int diff;

	if (!show_timestamp(dest->level))
		return NULL;

	t = time(NULL);

	if (timestamp_timeout > 0) {
		diff = t - dest->window->last_timestamp;
		dest->window->last_timestamp = t;
		if (diff < timestamp_timeout)
			return NULL;
	}

	tm = localtime(&t);
	return output_format_text(dest, IRCTXT_TIMESTAMP,
				  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
				  tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static char *get_server_tag(WINDOW_REC *window, SERVER_REC *server)
{
	if (server == NULL || servers == NULL || servers->next == NULL ||
	    (window->active != NULL && window->active->server == server))
		return NULL;

	return g_strdup_printf("[%s] ", server->tag);
}

static void sig_print_text(WINDOW_REC *window, SERVER_REC *server, const char *target, gpointer level, const char *text)
{
    TEXT_DEST_REC dest;
    gchar *dup, *ptr, type, *str, *timestamp, *servertag;
    gint fgcolor, bgcolor;
    gint flags;

    g_return_if_fail(text != NULL);
    g_return_if_fail(window != NULL);

    dest.window = window;
    dest.server = server;
    dest.channel = target;
    dest.level = GPOINTER_TO_INT(level);

    flags = 0; fgcolor = -1; bgcolor = -1; type = '\0';
    window->last_line = time(NULL);
    newline(window);

    timestamp = get_timestamp(&dest);
    servertag = get_server_tag(window, server);
    str = g_strconcat(timestamp != NULL ? timestamp : "",
		      servertag != NULL ? servertag : "",
		      text, NULL);
    g_free_not_null(timestamp);
    g_free_not_null(servertag);

    dup = str;
    while (*str != '\0')
    {
	for (ptr = str; *ptr != '\0'; ptr++)
	{
            if (is_color_code(*ptr))
            {
                type = *ptr;
                *ptr++ = '\0';
                break;
	    }

            *ptr = (gchar) translation_in[(gint) (guchar) *ptr];
	}

        if (type == 7)
        {
            /* bell */
            if (settings_get_bool("bell_beeps"))
                flags |= PRINTFLAG_BEEP;
        }
        if (*str != '\0' || flags & PRINTFLAG_BEEP)
        {
            signal_emit_id(signal_gui_print_text, 6, window,
                        GINT_TO_POINTER(fgcolor), GINT_TO_POINTER(bgcolor),
                        GINT_TO_POINTER(flags), str, level);
            flags &= ~(PRINTFLAG_BEEP|PRINTFLAG_INDENT);
        }
        if (*ptr == '\0') break;

        switch (type)
        {
            case 2:
                /* bold */
                if (!hide_text_style)
                    flags ^= PRINTFLAG_BOLD;
                break;
	    case 6:
		/* blink */
                if (!hide_text_style)
                    flags ^= PRINTFLAG_BLINK;
                break;
	    case 15:
                /* remove all styling */
		flags &= PRINTFLAG_BEEP;
		fgcolor = bgcolor = -1;
		break;
	    case 22:
                /* reverse */
                if (!hide_text_style)
                    flags ^= PRINTFLAG_REVERSE;
                break;
            case 31:
                /* underline */
                if (!hide_text_style)
                    flags ^= PRINTFLAG_UNDERLINE;
            case 27:
                /* ansi color code */
                ptr = convert_ansi(ptr, &fgcolor, &bgcolor, &flags);
                break;
            case 4:
                /* user specific colors */
		flags &= ~PRINTFLAG_MIRC_COLOR;
                if ((signed char) *ptr == -1)
                {
		    ptr++;
		    if ((signed char) *ptr == -1)
		    {
			fgcolor = bgcolor = -1;
			flags &= PRINTFLAG_INDENT;
		    }
                    else if (*ptr == 1)
                        flags ^= PRINTFLAG_BOLD;
                    else if (*ptr == 2)
                        flags ^= PRINTFLAG_UNDERLINE;
                    else if (*ptr == 3)
                        flags ^= PRINTFLAG_REVERSE;
                    else if (*ptr == 4)
                        flags |= PRINTFLAG_INDENT;
                }
                else
		{
		    if ((signed char) *ptr != -2)
		    {
			fgcolor = (guchar) *ptr-1;
			if (fgcolor <= 7)
			    flags &= ~PRINTFLAG_BOLD;
			else
			{
			    /* bold */
			    if (fgcolor != 8) fgcolor -= 8;
			    flags |= PRINTFLAG_BOLD;
			}
		    }
                    ptr++;
		    if ((signed char) *ptr != -2)
			bgcolor = (signed char) *ptr == -1 ? -1 : *ptr-1;
                }
                ptr++;
                break;
	    case 3:
                if (*ptr < 17)
                {
		    /* mostly just for irssi's internal use.. */
		    fgcolor = (*ptr++)-1;
		    if (*ptr == 0 || *ptr >= 17)
			bgcolor = -1;
		    else
			bgcolor = (*ptr++)-1;
		    if (fgcolor & 8)
			flags |= PRINTFLAG_BOLD;
		    else
			flags &= ~PRINTFLAG_BOLD;
		    break;
		}

                /* MIRC color */
                if (hide_text_style)
                {
                    /* don't show them. */
                    skip_mirc_color(&ptr);
                    break;
                }

		flags |= PRINTFLAG_MIRC_COLOR;
		if (!isdigit((gint) *ptr) && *ptr != ',')
		{
		    fgcolor = -1;
		    bgcolor = -1;
		}
		else
		{
		    /* foreground color */
		    if (*ptr != ',')
		    {
			fgcolor = *ptr++-'0';
			if (isdigit((gint) *ptr))
			    fgcolor = fgcolor*10 + (*ptr++-'0');
		    }
		    if (*ptr == ',')
		    {
			/* back color */
			bgcolor = 0;
			if (!isdigit((gint) *++ptr))
			    bgcolor = -1;
			else
			{
			    bgcolor = *ptr++-'0';
			    if (isdigit((gint) *ptr))
				bgcolor = bgcolor*10 + (*ptr++-'0');
			}
		    }
		}
                break;
        }

        str = ptr;
    }
    g_free(dup);
    signal_emit_id(signal_print_text_finished, 1, window);
}

void printtext_multiline(void *server, const char *channel, int level, const char *format, const char *text)
{
	char **lines, **tmp;

	lines = g_strsplit(text, "\n", -1);
        for (tmp = lines; *tmp != NULL; tmp++)
		printtext(NULL, NULL, MSGLEVEL_NEVER, format, *tmp);
	g_strfreev(lines);
}

static void sig_gui_dialog(const char *type, const char *text)
{
	char *format;

	if (g_strcasecmp(type, "warning") == 0)
		format = _("%_Warning:%_ %s");
	else if (g_strcasecmp(type, "error") == 0)
		format = _("%_Error:%_ %s");
	else
		format = "%s";

        printtext_multiline(NULL, NULL, MSGLEVEL_NEVER, format, text);
}

static void read_settings(void)
{
	timestamps = settings_get_bool("timestamps");
	timestamp_timeout = settings_get_int("timestamp_timeout");
	msgs_timestamps = settings_get_bool("msgs_timestamps");
	hide_text_style = settings_get_bool("hide_text_style");
}

void printtext_init(void)
{
	settings_add_int("misc", "timestamp_timeout", 0);

	signal_gui_print_text = module_get_uniq_id_str("signals", "gui print text");
	signal_print_text_stripped = module_get_uniq_id_str("signals", "print text stripped");
	signal_print_text = module_get_uniq_id_str("signals", "print text");
	signal_print_text_finished = module_get_uniq_id_str("signals", "print text finished");

	read_settings();
	signal_add("print text", (SIGNAL_FUNC) sig_print_text);
	signal_add("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void printtext_deinit(void)
{
	signal_remove("print text", (SIGNAL_FUNC) sig_print_text);
	signal_remove("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
