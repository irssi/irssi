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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/modules.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/core/levels.h>
#include <irssi/src/core/servers.h>

#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/printtext.h>

static int beep_msg_level, beep_msg_level_ignore, beep_when_away, beep_when_window_active;

static int signal_gui_print_text_finished;
static int signal_print_starting;
static int signal_print_text;
static int signal_print_format;
static int signal_print_noformat;
static int signal_window_hilight_check;

static int sending_print_starting;

static void print_line(TEXT_DEST_REC *dest, const char *text, int formatted);

void printformat_module_dest_args(const char *module, TEXT_DEST_REC *dest,
				  int formatnum, va_list va)
{
	char *arglist[MAX_FORMAT_PARAMS];
	char buffer[DEFAULT_FORMAT_ARGLIST_SIZE];
	FORMAT_REC *formats;

	formats = g_hash_table_lookup(default_formats, module);
	format_read_arglist(va, &formats[formatnum],
			    arglist, sizeof(arglist)/sizeof(char *),
			    buffer, sizeof(buffer));

	printformat_module_dest_charargs(module, dest, formatnum, arglist);
}

void printformat_module_dest_charargs(const char *module, TEXT_DEST_REC *dest,
				      int formatnum, char **arglist)
{
	THEME_REC *theme;

	theme = window_get_theme(dest->window);

	if (!sending_print_starting) {
		sending_print_starting = TRUE;
		signal_emit_id(signal_print_starting, 1, dest);
                sending_print_starting = FALSE;
	}

	signal_emit_id(signal_print_format, 5, theme, module,
		       dest, GINT_TO_POINTER(formatnum), arglist);
}

void printformat_module_dest(const char *module, TEXT_DEST_REC *dest,
			     int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_dest_args(module, dest, formatnum, va);
	va_end(va);
}

void printformat_module_args(const char *module, void *server,
			     const char *target, int level,
			     int formatnum, va_list va)
{
	TEXT_DEST_REC dest;

	format_create_dest(&dest, server, target, level, NULL);
	printformat_module_dest_args(module, &dest, formatnum, va);
}

void printformat_module(const char *module, void *server, const char *target,
			int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_args(module, server, target, level, formatnum, va);
	va_end(va);
}

void printformat_module_window_args(const char *module, WINDOW_REC *window,
				    int level, int formatnum, va_list va)
{
	TEXT_DEST_REC dest;

	format_create_dest(&dest, NULL, NULL, level, window);
	printformat_module_dest_args(module, &dest, formatnum, va);
}

void printformat_module_window(const char *module, WINDOW_REC *window,
			       int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_window_args(module, window, level, formatnum, va);
	va_end(va);
}

void printformat_module_gui_args(const char *module, int formatnum, va_list va)
{
	TEXT_DEST_REC dest;
	char *arglist[MAX_FORMAT_PARAMS];
	char buffer[DEFAULT_FORMAT_ARGLIST_SIZE];
	FORMAT_REC *formats;
        char *str;

	g_return_if_fail(module != NULL);

        memset(&dest, 0, sizeof(dest));

	formats = g_hash_table_lookup(default_formats, module);
	format_read_arglist(va, &formats[formatnum],
			    arglist, sizeof(arglist)/sizeof(char *),
			    buffer, sizeof(buffer));

	str = format_get_text_theme_charargs(window_get_theme(dest.window),
					     module, &dest,
					     formatnum, arglist);
	if (*str != '\0') format_send_to_gui(&dest, str);
	g_free(str);
}

void printformat_module_gui(const char *module, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
        printformat_module_gui_args(module, formatnum, va);
	va_end(va);
}

/* append string to `out', expand newlines. */
static void printtext_append_str(TEXT_DEST_REC *dest, GString *out,
				 const char *str)
{
	while (*str != '\0') {
		if (*str != '\n')
			g_string_append_c(out, *str);
		else {
			print_line(dest, out->str, 0);
			g_string_truncate(out, 0);
		}
		str++;
	}
}

static char *printtext_get_args(TEXT_DEST_REC *dest, const char *str,
				va_list va)
{
	GString *out;
	char *ret;
	int adv;

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
			g_string_append_printf(out, "%d", d);
			break;
		}
		case 'f': {
			double f = (double) va_arg(va, double);
			g_string_append_printf(out, "%0.2f", f);
			break;
		}
		case 'u': {
			unsigned int d =
				(unsigned int) va_arg(va, unsigned int);
			g_string_append_printf(out, "%u", d);
			break;
                }
		case 'l': {
			long d = (long) va_arg(va, long);

			if (*++str != 'd' && *str != 'u') {
				g_string_append_printf(out, "%ld", d);
				str--;
			} else {
				if (*str == 'd')
					g_string_append_printf(out, "%ld", d);
				else
					g_string_append_printf(out, "%lu", d);
			}
			break;
		}
		default:
			adv = format_expand_styles(out, &str, &dest->flags);
			if (!adv) {
				g_string_append_c(out, '%');
				g_string_append_c(out, *str);
			} else {
				str += adv - 1;
			}
			break;
		}
	}

	ret = g_string_free_and_steal(out);
	return ret;
}

static char *printtext_expand_formats(const char *str, int *flags)
{
	GString *out;
	char *ret;
	int adv;

	out = g_string_new(NULL);
	for (; *str != '\0'; str++) {
		if (*str != '%') {
			g_string_append_c(out, *str);
			continue;
		}

		if (*++str == '\0')
			break;

		adv = format_expand_styles(out, &str, flags);
		if (!adv) {
			g_string_append_c(out, '%');
			g_string_append_c(out, *str);
		} else {
		     str += adv - 1;
		}
	}

	ret = g_string_free_and_steal(out);
	return ret;
}

static void printtext_dest_args(TEXT_DEST_REC *dest, const char *text, va_list va)
{
	char *str;

	if (!sending_print_starting) {
		sending_print_starting = TRUE;
		signal_emit_id(signal_print_starting, 1, dest);
                sending_print_starting = FALSE;
	}

	str = printtext_get_args(dest, text, va);
	print_line(dest, str, 0);
	g_free(str);
}

void printtext_dest(TEXT_DEST_REC *dest, const char *text, ...)
{
	va_list va;

	va_start(va, text);
	printtext_dest_args(dest, text, va);
	va_end(va);
}

/* Write text to target - convert color codes */
void printtext(void *server, const char *target, int level, const char *text, ...)
{
	TEXT_DEST_REC dest;
	va_list va;

	g_return_if_fail(text != NULL);

        format_create_dest(&dest, server, target, level, NULL);

	va_start(va, text);
	printtext_dest_args(&dest, text, va);
	va_end(va);
}

/* Like printtext(), but don't handle %s etc. */
void printtext_string(void *server, const char *target, int level, const char *text)
{
	TEXT_DEST_REC dest;
        char *str;

	g_return_if_fail(text != NULL);

        format_create_dest(&dest, server, target, level, NULL);

	if (!sending_print_starting) {
		sending_print_starting = TRUE;
		signal_emit_id(signal_print_starting, 1, &dest);
                sending_print_starting = FALSE;
	}

        str = printtext_expand_formats(text, &dest.flags);
	print_line(&dest, str, 0);
	g_free(str);
}

/* Like printtext_window(), but don't handle %s etc. */
void printtext_string_window(WINDOW_REC *window, int level, const char *text)
{
	TEXT_DEST_REC dest;
        char *str;

	g_return_if_fail(text != NULL);

	format_create_dest(&dest, NULL, NULL, level,
			   window != NULL ? window : active_win);

	if (!sending_print_starting) {
		sending_print_starting = TRUE;
		signal_emit_id(signal_print_starting, 1, &dest);
                sending_print_starting = FALSE;
	}

        str = printtext_expand_formats(text, &dest.flags);
	print_line(&dest, str, 0);
	g_free(str);
}

void printtext_window(WINDOW_REC *window, int level, const char *text, ...)
{
	TEXT_DEST_REC dest;
	va_list va;

	g_return_if_fail(text != NULL);

	format_create_dest(&dest, NULL, NULL, level,
			   window != NULL ? window : active_win);

	va_start(va, text);
	printtext_dest_args(&dest, text, va);
	va_end(va);
}

void printtext_gui(const char *text)
{
	TEXT_DEST_REC dest;
        char *str;

	g_return_if_fail(text != NULL);

        memset(&dest, 0, sizeof(dest));

	str = printtext_expand_formats(text, &dest.flags);
	format_send_to_gui(&dest, str);
	g_free(str);
}

/* Like printtext_gui(), but don't expand % codes. */
void printtext_gui_internal(const char *str)
{
	TEXT_DEST_REC dest;

	g_return_if_fail(str != NULL);

        memset(&dest, 0, sizeof(dest));

	format_send_to_gui(&dest, str);
}

static void msg_beep_check(TEXT_DEST_REC *dest)
{
	if (dest->level != 0 && (dest->level & MSGLEVEL_NO_ACT) == 0 &&
	    (beep_msg_level & dest->level) &&
	    (beep_when_away || (dest->server != NULL &&
				!dest->server->usermode_away)) &&
	    (beep_when_window_active || dest->window != active_win)) {
		if (beep_msg_level_ignore & MSGLEVEL_HIDDEN) {
			int cb_ignore = 0;
			if (signal_emit_id(signal_window_hilight_check, 4, dest, NULL, NULL,
			                   &cb_ignore),
			    cb_ignore) {
				return;
			}
		} else if (beep_msg_level_ignore & dest->level) {
			return;
		}

		signal_emit("beep", 0);
	}
}

static void sig_print_text(TEXT_DEST_REC *dest, const char *text)
{
        THEME_REC *theme;
	char *str, *tmp;

	g_return_if_fail(dest != NULL);
	g_return_if_fail(text != NULL);

	if (dest->window == NULL) {
                str = strip_codes(text);
#ifndef SUPPRESS_PRINTF_FALLBACK
		printf("## NO WINDOWS: %s\n", str);
#endif
                g_free(str);
                return;
	}

	msg_beep_check(dest);

        if ((dest->level & MSGLEVEL_NEVER) == 0)
		dest->window->last_line = time(NULL);

	/* add timestamp/server tag here - if it's done in print_line()
	   it would be written to log files too */
        theme = window_get_theme(dest->window);
	tmp = format_get_line_start(theme, dest, time(NULL));
	str = !theme->info_eol ? format_add_linestart(text, tmp) :
		format_add_lineend(text, tmp);

	g_free_not_null(tmp);

	format_send_to_gui(dest, str);
	g_free(str);

	signal_emit_id(signal_gui_print_text_finished, 2, dest->window, dest);
}

static void sig_print_format(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest,
                             void *formatnump, char **arglist)
{
	int formatnum;
	char *str;

	formatnum = GPOINTER_TO_INT(formatnump);
	str = format_get_text_theme_charargs(theme, module, dest, formatnum, arglist);
	if (str != NULL && *str != '\0')
		print_line(dest, str, 1);

	g_free(str);
}

static void sig_print_noformat(TEXT_DEST_REC *dest, const char *text)
{
	THEME_REC *theme;
	char *str, *tmp, *stripped;

	theme = window_get_theme(dest->window);
	tmp = format_get_level_tag(theme, dest);
	str = !theme->info_eol ? format_add_linestart(text, tmp) : format_add_lineend(text, tmp);
	g_free_not_null(tmp);

	/* send both the formatted + stripped (for logging etc.) */
	stripped = strip_codes(str);
	signal_emit_id(signal_print_text, 3, dest, str, stripped);

	g_free_and_null(dest->hilight_color);

	g_free(str);
	g_free(stripped);
}

static void print_line(TEXT_DEST_REC *dest, const char *text, int formatted)
{
	g_return_if_fail(dest != NULL);
	g_return_if_fail(text != NULL);

	if (!formatted)
		signal_emit_id(signal_print_noformat, 2, dest, text);
	else
		sig_print_noformat(dest, text);
}

void printtext_multiline(void *server, const char *target, int level,
			 const char *format, const char *text)
{
	char **lines, **tmp;

	g_return_if_fail(format != NULL);
	g_return_if_fail(text != NULL);

	lines = g_strsplit(text, "\n", -1);
        for (tmp = lines; *tmp != NULL; tmp++)
		printtext(NULL, NULL, level, format, *tmp);
	g_strfreev(lines);
}

static void sig_gui_dialog(const char *type, const char *text)
{
	char *format;

	if (g_ascii_strcasecmp(type, "warning") == 0)
		format = "%_Warning:%_ %s";
	else if (g_ascii_strcasecmp(type, "error") == 0)
		format = "%_Error:%_ %s";
	else
		format = "%s";

        printtext_multiline(NULL, NULL, MSGLEVEL_NEVER, format, text);
}

static void read_settings(void)
{
	beep_msg_level = settings_get_level("beep_msg_level");
	beep_msg_level_ignore = settings_get_level_negative("beep_msg_level");
	beep_when_away = settings_get_bool("beep_when_away");
        beep_when_window_active = settings_get_bool("beep_when_window_active");
}

void printtext_init(void)
{
	sending_print_starting = FALSE;
	signal_gui_print_text_finished = signal_get_uniq_id("gui print text finished");
	signal_print_starting = signal_get_uniq_id("print starting");
	signal_print_text = signal_get_uniq_id("print text");
	signal_print_format = signal_get_uniq_id("print format");
	signal_print_noformat = signal_get_uniq_id("print noformat");
	signal_window_hilight_check = signal_get_uniq_id("window hilight check");

	read_settings();
	signal_add("print text", (SIGNAL_FUNC) sig_print_text);
	signal_add("print format", (SIGNAL_FUNC) sig_print_format);
	signal_add("print noformat", (SIGNAL_FUNC) sig_print_noformat);
	signal_add("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void printtext_deinit(void)
{
	signal_remove("print text", (SIGNAL_FUNC) sig_print_text);
	signal_remove("print format", (SIGNAL_FUNC) sig_print_format);
	signal_remove("print noformat", (SIGNAL_FUNC) sig_print_noformat);
	signal_remove("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
