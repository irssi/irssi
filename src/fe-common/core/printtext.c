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
#include "settings.h"

#include "levels.h"
#include "servers.h"

#include "translation.h"
#include "themes.h"
#include "windows.h"
#include "printtext.h"

static int beep_msg_level, beep_when_away;
static int timestamps, msgs_timestamps, hide_text_style;
static int timestamp_timeout;

static int signal_gui_print_text;
static int signal_print_text_stripped;
static int signal_print_text;
static int signal_print_text_finished;
static int signal_print_format;

static void print_line(TEXT_DEST_REC *dest, const char *text);

void printbeep(void)
{
	signal_emit_id(signal_gui_print_text, 6, active_win, NULL, NULL,
		       GINT_TO_POINTER(PRINTFLAG_BEEP), "", MSGLEVEL_NEVER);
}

static void get_mirc_color(const char **str, int *fg_ret, int *bg_ret)
{
	int fg, bg;

	fg = fg_ret == NULL ? -1 : *fg_ret;
	bg = bg_ret == NULL ? -1 : *bg_ret;

	if (!isdigit((int) **str) && **str != ',') {
		fg = -1;
		bg = -1;
	} else {
		/* foreground color */
		if (**str != ',') {
			fg = **str-'0';
                        (*str)++;
			if (isdigit((int) **str)) {
				fg = fg*10 + (**str-'0');
				(*str)++;
			}
		}
		if (**str == ',') {
			/* background color */
			(*str)++;
			if (!isdigit((int) **str))
				bg = -1;
			else {
				bg = **str-'0';
				(*str)++;
				if (isdigit((int) **str)) {
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

		if (!IS_COLOR_CODE(*p))
			*out++ = *p;
	}

	*out = '\0';
	return str;
}

/* parse ANSI color string */
static char *get_ansi_color(THEME_REC *theme, char *str,
			    int *fg_ret, int *bg_ret, int *flags_ret)
{
	static char ansitab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	char *start;
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

		if (isdigit((int) *str)) {
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
			flags &= ~(PRINTFLAG_BEEP|PRINTFLAG_INDENT);
			break;
		case 1:
			/* hilight */
			flags |= PRINTFLAG_BOLD;
			break;
		case 5:
			/* blink */
			flags |= PRINTFLAG_BLINK;
			break;
		case 7:
			/* reverse */
			flags |= PRINTFLAG_REVERSE;
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
			if (fg_ret != NULL) *fg_ret = fg;
			if (bg_ret != NULL) *bg_ret = bg;
			if (flags_ret != NULL) *flags_ret = flags;

			str++;
			break;
		}
	}

	return str;
}

void printformat_module_args(const char *module, void *server,
			     const char *target, int level,
			     int formatnum, va_list va)
{
	THEME_REC *theme;
	TEXT_DEST_REC dest;
	char *str;

	format_create_dest(&dest, server, target, level, NULL);
	theme = dest.window->theme == NULL ? current_theme :
		dest.window->theme;

	signal_emit_id(signal_print_format, 5, theme, module,
		       &dest, GINT_TO_POINTER(formatnum), va);

        str = format_get_text_theme_args(theme, module, &dest, formatnum, va);
	if (*str != '\0') print_line(&dest, str);
	g_free(str);
}

void printformat_module(const char *module, void *server, const char *target, int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_args(module, server, target, level, formatnum, va);
	va_end(va);
}

void printformat_module_window_args(const char *module, WINDOW_REC *window,
				    int level, int formatnum, va_list va)
{
	THEME_REC *theme;
	TEXT_DEST_REC dest;
	char *str;

	format_create_dest(&dest, NULL, NULL, level, window);
	theme = window->theme == NULL ? current_theme :
		window->theme;

	signal_emit_id(signal_print_format, 5, theme, module,
		       &dest, GINT_TO_POINTER(formatnum), va);

        str = format_get_text_theme_args(theme, module, &dest, formatnum, va);
	if (*str != '\0') print_line(&dest, str);
	g_free(str);
}

void printformat_module_window(const char *module, WINDOW_REC *window,
			       int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_window_args(module, window, level, formatnum, va);
	va_end(va);
}

static void print_line(TEXT_DEST_REC *dest, const char *text)
{
	void *levelp;
	char *str, *tmp;

	g_return_if_fail(dest != NULL);
	g_return_if_fail(text != NULL);

	tmp = format_get_line_start(current_theme, dest);
	str = format_add_linestart(text, tmp);
	g_free_not_null(tmp);

	levelp = GINT_TO_POINTER(dest->level);

	/* send the plain text version for logging etc.. */
	tmp = strip_codes(str);
	signal_emit_id(signal_print_text_stripped, 5, dest->window, dest->server, dest->target, levelp, tmp);
	g_free(tmp);

	signal_emit_id(signal_print_text, 5, dest->window, dest->server, dest->target, levelp, str);
	g_free(str);
}

/* append string to `out', expand newlines. */
static void printtext_append_str(TEXT_DEST_REC *dest, GString *out, const char *str)
{
	while (*str != '\0') {
		if (*str != '\n')
			g_string_append_c(out, *str);
		else {
			print_line(dest, out->str);
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
			if (!format_expand_styles(out, *str, dest)) {
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

/* Write text to target - convert color codes */
void printtext(void *server, const char *target, int level, const char *text, ...)
{
	TEXT_DEST_REC dest;
	char *str;
	va_list va;

	g_return_if_fail(text != NULL);

        format_create_dest(&dest, server, target, level, NULL);

	va_start(va, text);
	str = printtext_get_args(&dest, text, va);
	va_end(va);

	print_line(&dest, str);
	g_free(str);
}

void printtext_window(WINDOW_REC *window, int level, const char *text, ...)
{
	TEXT_DEST_REC dest;
	char *str;
	va_list va;

	g_return_if_fail(text != NULL);

	format_create_dest(&dest, NULL, NULL, level,
			   window != NULL ? window : active_win);

	va_start(va, text);
	str = printtext_get_args(&dest, text, va);
	va_end(va);

	print_line(&dest, str);
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
	((level & (MSGLEVEL_NEVER|MSGLEVEL_LASTLOG)) == 0 && \
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
	return format_get_text_theme(NULL, MODULE_NAME, dest, IRCTXT_TIMESTAMP,
				     tm->tm_year+1900,
				     tm->tm_mon+1, tm->tm_mday,
				     tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static char *get_server_tag(TEXT_DEST_REC *dest)
{
	SERVER_REC *server;

	server = dest->server;

	if (server == NULL || servers == NULL || servers->next == NULL ||
	    (dest->window->active != NULL && dest->window->active->server == server))
		return NULL;

	return format_get_text_theme(NULL, MODULE_NAME, dest,
				     IRCTXT_SERVERTAG, server->tag);
}

static void msg_beep_check(SERVER_REC *server, int level)
{
	if (level != 0 && (level & MSGLEVEL_NOHILIGHT) == 0 &&
	    (beep_msg_level & level) &&
	    (beep_when_away || (server != NULL && !server->usermode_away))) {
		printbeep();
	}
}

static char *fix_line_start(TEXT_DEST_REC *dest, const char *text)
{
	char *timestamp, *servertag;
	char *linestart, *str;

	timestamp = get_timestamp(dest);
	servertag = get_server_tag(dest);

	if (timestamp == NULL && servertag == NULL)
		return g_strdup(text);

	linestart = g_strconcat(timestamp != NULL ? timestamp : "",
				servertag, NULL);
	str = format_add_linestart(text, linestart);
	g_free(linestart);

	g_free_not_null(timestamp);
	g_free_not_null(servertag);
	return str;
}

static void sig_print_text(WINDOW_REC *window, SERVER_REC *server,
			   const char *target, gpointer level,
			   const char *text)
{
	TEXT_DEST_REC dest;
	char *dup, *ptr, type, *str;
	int fgcolor, bgcolor;
	int flags;

	g_return_if_fail(text != NULL);
	g_return_if_fail(window != NULL);

	format_create_dest(&dest, server, target,
			   GPOINTER_TO_INT(level), window);
	msg_beep_check(server, dest.level);

	window->last_line = time(NULL);
	newline(window);

	dup = str = fix_line_start(&dest, text);
	flags = 0; fgcolor = -1; bgcolor = -1; type = '\0';
	while (*str != '\0') {
		for (ptr = str; *ptr != '\0'; ptr++) {
			if (IS_COLOR_CODE(*ptr)) {
				type = *ptr;
				*ptr++ = '\0';
				break;
			}

			*ptr = (char) translation_in[(int) (unsigned char) *ptr];
		}

		if (type == 7) {
			/* bell */
			if (settings_get_bool("bell_beeps"))
				flags |= PRINTFLAG_BEEP;
		}
		if (*str != '\0' || flags & PRINTFLAG_BEEP) {
                        /* send the text to gui handler */
			signal_emit_id(signal_gui_print_text, 6, window,
				       GINT_TO_POINTER(fgcolor),
				       GINT_TO_POINTER(bgcolor),
				       GINT_TO_POINTER(flags), str, level);
			flags &= ~(PRINTFLAG_BEEP|PRINTFLAG_INDENT);
		}

		if (*ptr == '\0')
			break;

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
			ptr = get_ansi_color(window->theme == NULL ?
					     current_theme : window->theme,
					     ptr,
					     hide_text_style ? NULL : &fgcolor,
					     hide_text_style ? NULL : &bgcolor,
					     hide_text_style ? NULL : &flags);
			break;
		case 4:
			/* user specific colors */
			flags &= ~PRINTFLAG_MIRC_COLOR;
			switch (*ptr) {
			case FORMAT_STYLE_UNDERLINE:
				flags ^= PRINTFLAG_UNDERLINE;
				break;
			case FORMAT_STYLE_BOLD:
				flags ^= PRINTFLAG_BOLD;
				break;
			case FORMAT_STYLE_REVERSE:
				flags ^= PRINTFLAG_REVERSE;
				break;
			case FORMAT_STYLE_INDENT:
				flags |= PRINTFLAG_INDENT;
				break;
			case FORMAT_STYLE_DEFAULTS:
				fgcolor = bgcolor = -1;
				flags &= PRINTFLAG_INDENT;
				break;
			default:
				if (*ptr != FORMAT_COLOR_NOCHANGE) {
					fgcolor = (unsigned char) *ptr-'0';
					if (fgcolor <= 7)
						flags &= ~PRINTFLAG_BOLD;
					else {
						/* bold */
						if (fgcolor != 8) fgcolor -= 8;
						flags |= PRINTFLAG_BOLD;
					}
				}
				ptr++;
				if (*ptr != FORMAT_COLOR_NOCHANGE)
					bgcolor = *ptr-'0';
			}
			ptr++;
			break;
		case 3:
			/* MIRC color */
			get_mirc_color((const char **) &ptr,
				       hide_text_style ? NULL : &fgcolor,
				       hide_text_style ? NULL : &bgcolor);
			if (!hide_text_style)
				flags |= PRINTFLAG_MIRC_COLOR;
			break;
		}

		str = ptr;
	}
	g_free(dup);
	signal_emit_id(signal_print_text_finished, 1, window);
}

void printtext_multiline(void *server, const char *target, int level,
			 const char *format, const char *text)
{
	char **lines, **tmp;

	g_return_if_fail(format != NULL);
	g_return_if_fail(text != NULL);

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
	beep_msg_level = level2bits(settings_get_str("beep_on_msg"));
	beep_when_away = settings_get_bool("beep_when_away");
}

void printtext_init(void)
{
	settings_add_int("misc", "timestamp_timeout", 0);

	signal_gui_print_text = signal_get_uniq_id("gui print text");
	signal_print_text_stripped = signal_get_uniq_id("print text stripped");
	signal_print_text = signal_get_uniq_id("print text");
	signal_print_text_finished = signal_get_uniq_id("print text finished");
	signal_print_format = signal_get_uniq_id("print format");

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
