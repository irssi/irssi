/*
 printtext.c : irssi

    Copyright (C) 1999 Timo Sirainen

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

static gboolean toggle_show_timestamps, toggle_show_msgs_timestamps, toggle_hide_text_style;
static gint printtag;
static gchar ansitab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };

static gint signal_gui_print_text;
static gint signal_print_text_stripped;
static gint signal_print_text;
static gint signal_print_text_finished;

void printbeep(void)
{
    signal_emit_id(signal_gui_print_text, 6, active_win, NULL, NULL,
		GINT_TO_POINTER(PRINTFLAG_BEEP), "", MSGLEVEL_NEVER);
}

/* parse ANSI color string */
static char *convert_ansi(char *str, int *fgcolor, int *bgcolor, int *flags)
{
    gchar *start;
    gint fg, bg, fl, num;

    if (*str != '[') return str;

    start = str;

    fg = *fgcolor < 0 ? current_theme->default_color : *fgcolor;
    bg = *bgcolor < 0 ? -1 : *bgcolor;
    fl = *flags;

    str++; num = 0;
    for (;; str++)
    {
        if (*str == '\0') return start;

        if (isdigit((gint) *str))
        {
            num = num*10 + (*str-'0');
            continue;
        }

        if (*str != ';' && *str != 'm') return start;

        switch (num)
        {
            case 0:
                /* reset colors back to default */
                fg = current_theme->default_color;
                bg = -1;
                break;
            case 1:
                /* hilight */
                fg |= 8;
                break;
            case 5:
                /* blink */
                bg = bg == -1 ? 8 : bg | 8;
                break;
            case 7:
                /* reverse */
                fl |= PRINTFLAG_REVERSE;
                break;
            default:
                if (num >= 30 && num <= 37)
                    fg = (fg & 0xf8) + ansitab[num-30];
                if (num >= 40 && num <= 47)
                {
                    if (bg == -1) bg = 0;
                    bg = (bg & 0xf8) + ansitab[num-40];
                }
                break;
        }
        num = 0;

        if (*str == 'm')
        {
            if (!toggle_hide_text_style)
            {
                *fgcolor = fg;
                *bgcolor = bg == -1 ? -1 : bg;
                *flags = fl;
            }
            str++;
            break;
        }
    }

    return str;
}

#define IN_COLOR_CODE 2
#define IN_SECOND_CODE 4
char *strip_codes(const char *input)
{
    const char *p;
    gchar *str, *out;
    gint loop_state;

    loop_state = 0;
    out = str = g_strdup(input);
    for (p = input; *p != '\0'; p++) /* Going through the string till the end k? */
    {
	if (*p == '\003')
	{
	    if (p[1] < 17 && p[1] > 0)
	    {
		p++;
		if (p[1] < 17 && p[1] > 0) p++;
		continue;
	    }
	    loop_state = IN_COLOR_CODE;
	    continue;
	}

	if (loop_state & IN_COLOR_CODE)
	{
	    if (isdigit( (gint) *p )) continue;
	    if (*p != ',' || (loop_state & IN_SECOND_CODE))
	    {
		/* we're no longer in a color code */
		*out++ = *p;
		loop_state &= ~IN_COLOR_CODE|IN_SECOND_CODE;
		continue;
	    }

	    /* we're in the second code */
	    loop_state |= IN_SECOND_CODE;
	    continue;

	}

	/* we're not in a color code that means we should add the character */
	if (*p == 4 && p[1] != '\0' && p[2] != '\0')
	{
	    p += 2;
	    continue;
	}

	if (*p == 2 || *p == 22 || *p == 27 || *p == 31 || *p == 15)
	    continue;
        *out++ = *p;
    }

    *out = '\0';
    return str;
}

static gboolean expand_styles(GString *out, char format, void *server, const char *channel, int level)
{
    static const char *backs = "01234567";
    static const char *fores = "krgybmcw";
    static const char *boldfores = "KRGYBMCW";
    gchar *p;

    /* p/P -> m/M */
    if (format == 'p')
	format = 'm';
    else if (format == 'P')
	format = 'M';

    switch (format)
    {
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
            printtext(server, channel, level, out->str);
            g_string_truncate(out, 0);
	    break;

	case '|':
	    /* Indent here mark */
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
	    if (p != NULL)
	    {
		g_string_append_c(out, 4);
		g_string_append_c(out, -2);
		g_string_append_c(out, ansitab[(gint) (p-backs)]+1);
		break;
	    }

	    /* check if it's a foreground color */
	    p = strchr(fores, format);
	    if (p != NULL)
	    {
		g_string_append_c(out, 4);
		g_string_append_c(out, ansitab[(gint) (p-fores)]+1);
		g_string_append_c(out, -2);
		break;
	    }

	    /* check if it's a bold foreground color */
	    p = strchr(boldfores, format);
	    if (p != NULL)
	    {
		g_string_append_c(out, 4);
		g_string_append_c(out, 8+ansitab[(gint) (p-boldfores)]+1);
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
	for (num = 0; num < format->params && num < arglist_size; num++) {
		switch (format->paramtypes[num]) {
		case FORMAT_STRING:
			arglist[num] = (char *) va_arg(va, char *);
			if (arglist[num] == NULL) {
				g_warning("output_format_text_args() : parameter %d is NULL", num);
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

static void output_format_text_args(GString *out, void *server, const char *channel, int level, FORMAT_REC *format, const char *text, va_list args)
{
	char *arglist[10];
	char buffer[200]; /* should be enough? (won't overflow even if it isn't) */

	const char *str;
	char code;
	int need_free;

	str = current_theme != NULL && text != NULL ? text : format->def;

	/* read all optional arguments to arglist[] list
	   so they can be used in any order.. */
	read_arglist(args, format,
		     arglist, sizeof(arglist)/sizeof(void*),
		     buffer, sizeof(buffer));

	code = 0;
	while (*str != '\0') {
		if (code == '%') {
			/* color code */
			if (!expand_styles(out, *str, server, channel, level)) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *str);
			}
			code = 0;
		} else if (code == '$') {
			/* argument */
			char *ret;

			ret = parse_special((char **) &str, active_win->active_server, active_win->active, arglist, &need_free, NULL);
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
}

static void output_format_text(GString *out, void *server, const char *channel, int level, int formatnum, ...)
{
	MODULE_THEME_REC *theme;
	va_list args;

	theme = g_hash_table_lookup(current_theme->modules, MODULE_FORMATS->tag);

	va_start(args, formatnum);
	output_format_text_args(out, server, channel, level,
				&MODULE_FORMATS[formatnum],
				theme == NULL ? NULL : theme->format[formatnum], args);
	va_end(args);
}

static void add_timestamp(WINDOW_REC *window, GString *out, void *server, const char *channel, int level)
{
	time_t t;
	struct tm *tm;
	GString *tmp;

	if (!(level != MSGLEVEL_NEVER && (toggle_show_timestamps || (toggle_show_msgs_timestamps && (level & MSGLEVEL_MSGS) != 0))))
		return;

	t = time(NULL);

	if ((t - window->last_timestamp) < settings_get_int("timestamp_timeout")) {
		window->last_timestamp = t;
		return;
	}
	window->last_timestamp = t;

	tmp = g_string_new(NULL);
	tm = localtime(&t);
	output_format_text(tmp, server, channel, level, IRCTXT_TIMESTAMP,
			   tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

	/* insert the timestamp right after \n */
	g_string_prepend(out, tmp->str);
	g_string_free(tmp, TRUE);
}

static void new_line_stuff(GString *out, void *server, const char *channel, int level)
{
	if ((level & (MSGLEVEL_CLIENTERROR|MSGLEVEL_CLIENTNOTICE)) != 0)
		output_format_text(out, server, channel, level, IRCTXT_LINE_START_IRSSI);
	else if ((level & (MSGLEVEL_MSGS|MSGLEVEL_PUBLIC|MSGLEVEL_NOTICES|MSGLEVEL_SNOTES|MSGLEVEL_CTCPS|MSGLEVEL_ACTIONS|MSGLEVEL_DCC|MSGLEVEL_CLIENTCRAP)) == 0 && level != MSGLEVEL_NEVER)
		output_format_text(out, server, channel, level, IRCTXT_LINE_START);
}

/* Write text to channel - convert color codes */
void printtext(void *server, const char *channel, int level, const char *str, ...)
{
    va_list args;
    GString *out;
    gchar *tmpstr;
    gint pros;

    g_return_if_fail(str != NULL);

    va_start(args, str);

    pros = 0;
    out = g_string_new(NULL);

    new_line_stuff(out, server, channel, level);
    for (; *str != '\0'; str++)
    {
        if (*str != '%')
        {
            g_string_append_c(out, *str);
            continue;
        }

        if (*++str == '\0') break;
        switch (*str)
        {
            /* standard parameters */
            case 's':
                {
                    gchar *s = (gchar *) va_arg(args, gchar *);
                    if (s && *s) g_string_append(out, s);
                    break;
                }
            case 'd':
                {
                    gint d = (gint) va_arg(args, gint);
                    g_string_sprintfa(out, "%d", d);
                    break;
                }
            case 'f':
                {
                    gdouble f = (gdouble) va_arg(args, gdouble);
                    g_string_sprintfa(out, "%0.2f", f);
                    break;
                }
            case 'u':
                {
                    guint d = (guint) va_arg(args, guint);
                    g_string_sprintfa(out, "%u", d);
                    break;
                }
            case 'l':
                {
                    gulong d = (gulong) va_arg(args, gulong);
                    if (*++str != 'd' && *str != 'u')
                    {
                        g_string_sprintfa(out, "%ld", d);
                        str--;
                    }
                    else
                    {
                        if (*str == 'd')
                            g_string_sprintfa(out, "%ld", d);
                        else
                            g_string_sprintfa(out, "%lu", d);
                    }
                    break;
                }
            default:
                if (!expand_styles(out, *str, server, channel, level))
                {
                    g_string_append_c(out, '%');
                    g_string_append_c(out, *str);
                }
                break;
        }
    }
    va_end(args);

    /* send the plain text version for logging.. */
    tmpstr = strip_codes(out->str);
    signal_emit_id(signal_print_text_stripped, 4, server, channel, GINT_TO_POINTER(level), tmpstr);
    g_free(tmpstr);

    signal_emit_id(signal_print_text, 4, server, channel, GINT_TO_POINTER(level), out->str);

    g_string_free(out, TRUE);
}

void printformat_format(FORMAT_REC *formats, void *server, const char *channel, int level, int formatnum, ...)
{
	MODULE_THEME_REC *theme;
	GString *out;
	va_list args;

	va_start(args, formatnum);
	out = g_string_new(NULL);

	theme = g_hash_table_lookup(current_theme->modules, formats->tag);

	output_format_text_args(out, server, channel, level,
				&formats[formatnum],
				theme == NULL ? NULL : theme->format[formatnum], args);
	if (out->len > 0) printtext(server, channel, level, "%s", out->str);

	g_string_free(out, TRUE);
	va_end(args);
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

static void sig_print_text(void *server, const char *target, gpointer level, const char *text)
{
    WINDOW_REC *window;
    GString *out;
    gchar *dup, *ptr, type, *str;
    gint fgcolor, bgcolor;
    gint flags;

    g_return_if_fail(text != NULL);

    window = window_find_closest(server, target, GPOINTER_TO_INT(level));
    g_return_if_fail(window != NULL);

    flags = 0; fgcolor = -1; bgcolor = -1; type = '\0';

    newline(window);

    out = g_string_new(text);
    if (server != NULL && servers != NULL && servers->next != NULL &&
	(window->active == NULL || window->active->server != server))
    {
	/* connected to more than one server and active server isn't the
	   same where the message came or we're in status/msgs/empty window -
	   prefix with a [server tag] */
	gchar *str;

	str = g_strdup_printf("[%s] ", ((SERVER_REC *) server)->tag);
	g_string_prepend(out, str);
	g_free(str);
    }

    add_timestamp(window, out, server, target, GPOINTER_TO_INT(level));

    dup = str = out->str;
    g_string_free(out, FALSE);

    while (*str != '\0')
    {
	for (ptr = str; *ptr != '\0'; ptr++)
	{
            if (*ptr == 2 || *ptr == 3 || *ptr == 4 || *ptr == 6 || *ptr == 7 || *ptr == 15 || *ptr == 22 || *ptr == 27 || *ptr == 31)
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
            if (settings_get_bool("toggle_bell_beeps"))
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
                if (!toggle_hide_text_style)
                    flags ^= PRINTFLAG_BOLD;
                break;
	    case 6:
		/* blink */
                if (!toggle_hide_text_style)
                    flags ^= PRINTFLAG_BLINK;
                break;
	    case 15:
                /* remove all styling */
		flags &= PRINTFLAG_BEEP;
		fgcolor = bgcolor = -1;
		break;
	    case 22:
                /* reverse */
                if (!toggle_hide_text_style)
                    flags ^= PRINTFLAG_REVERSE;
                break;
            case 31:
                /* underline */
                if (!toggle_hide_text_style)
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
                if (toggle_hide_text_style)
                {
                    /* don't show them. */
                    if (isdigit((gint) *ptr))
                    {
                        ptr++;
                        if (isdigit((gint) *ptr)) ptr++;
                        if (*ptr == ',')
                        {
                            ptr++;
                            if (isdigit((gint) *ptr))
                            {
                                ptr++;
                                if (isdigit((gint) *ptr)) ptr++;
                            }
                        }
                    }
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

static int sig_check_daychange(void)
{
    static gint lastday = -1;
    GSList *tmp;
    time_t t;
    struct tm *tm;

    if (!toggle_show_timestamps)
    {
        /* display day change notice only when using timestamps */
	return TRUE;
    }

    t = time(NULL);
    tm = localtime(&t);

    if (lastday == -1)
    {
	/* First check, don't display. */
	lastday = tm->tm_mday;
	return TRUE;
    }

    if (tm->tm_mday == lastday)
	return TRUE;

    /* day changed, print notice about it to every window */
    for (tmp = windows; tmp != NULL; tmp = tmp->next)
    {
	WINDOW_REC *win = tmp->data;

	printformat(win->active->server, win->active->name, MSGLEVEL_NEVER,
		    IRCTXT_DAYCHANGE, tm->tm_mday, tm->tm_mon+1, 1900+tm->tm_year);
    }
    lastday = tm->tm_mday;
    return TRUE;
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
    toggle_show_timestamps = settings_get_bool("toggle_show_timestamps");
    toggle_show_msgs_timestamps = settings_get_bool("toggle_show_msgs_timestamps");
    toggle_hide_text_style = settings_get_bool("toggle_hide_text_style");
}

void printtext_init(void)
{
    settings_add_int("misc", "timestamp_timeout", 0);

    signal_gui_print_text = module_get_uniq_id_str("signals", "gui print text");
    signal_print_text_stripped = module_get_uniq_id_str("signals", "print text stripped");
    signal_print_text = module_get_uniq_id_str("signals", "print text");
    signal_print_text_finished = module_get_uniq_id_str("signals", "print text finished");

    read_settings();
    printtag = g_timeout_add(30000, (GSourceFunc) sig_check_daychange, NULL);
    signal_add("print text", (SIGNAL_FUNC) sig_print_text);
    signal_add("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
    signal_add("setup changed", (SIGNAL_FUNC) read_settings);
    command_bind("beep", NULL, (SIGNAL_FUNC) printbeep);
}

void printtext_deinit(void)
{
    g_source_remove(printtag);
    signal_remove("print text", (SIGNAL_FUNC) sig_print_text);
    signal_remove("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
    signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
    command_unbind("beep", (SIGNAL_FUNC) printbeep);
}
