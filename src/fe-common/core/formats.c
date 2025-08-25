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
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/levels.h>
#include <irssi/src/core/servers.h>

#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/core/recode.h>
#include <irssi/src/core/utf8.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/refstrings.h>

static const char *format_backs = "04261537";
static const char *format_fores = "kbgcrmyw";
static const char *format_boldfores = "KBGCRMYW";
static const char *ext_color_al = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static int signal_gui_print_text;
static int hide_text_style, hide_server_tags, hide_colors;

/* Global recursion protection for nick column formatting */
static int nick_formatting_depth = 0;

static int timestamp_level;
static int timestamp_timeout;

static GHashTable *global_meta;

int format_find_tag(const char *module, const char *tag)
{
	FORMAT_REC *formats;
	int n;

	formats = g_hash_table_lookup(default_formats, module);
	if (formats == NULL)
		return -1;

	for (n = 0; formats[n].def != NULL; n++) {
		if (formats[n].tag != NULL && g_ascii_strcasecmp(formats[n].tag, tag) == 0)
			return n;
	}

	return -1;
}

static void format_expand_code(const char **format, GString *out, int *flags)
{
	int set;

	if (flags == NULL) {
		/* flags are being ignored - skip the code */
		while (**format != ']' && **format != '\0')
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
		else
			switch (**format) {
			case 's':
			case 'S':
				*flags |= !set            ? PRINT_FLAG_UNSET_LINE_START :
				          **format == 's' ? PRINT_FLAG_SET_LINE_START :
				                            PRINT_FLAG_SET_LINE_START_IRSSI;
				break;
			case 't':
				*flags |=
				    set ? PRINT_FLAG_SET_TIMESTAMP : PRINT_FLAG_UNSET_TIMESTAMP;
				break;
			case 'T':
				*flags |=
				    set ? PRINT_FLAG_SET_SERVERTAG : PRINT_FLAG_UNSET_SERVERTAG;
				break;
			}

		(*format)++;
	}
}

void format_ext_color(GString *out, int bg, int color)
{
	g_string_append_c(out, 4);
	if (bg && color < 0x10)
		g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
	if (color < 0x10)
		g_string_append_c(out, color + '0');
	else {
		if (color < 0x60)
			g_string_append_c(out, bg ? FORMAT_COLOR_EXT1_BG : FORMAT_COLOR_EXT1);
		else if (color < 0xb0)
			g_string_append_c(out, bg ? FORMAT_COLOR_EXT2_BG : FORMAT_COLOR_EXT2);
		else
			g_string_append_c(out, bg ? FORMAT_COLOR_EXT3_BG : FORMAT_COLOR_EXT3);
		g_string_append_c(out, FORMAT_COLOR_NOCHANGE + ((color - 0x10) % 0x50));
	}

	if (!bg && color < 0x10)
		g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
}

static void format_ext_color_unexpand(GString *out, gboolean bg, int base, char color)
{
	unsigned char value = base + (unsigned char) color - FORMAT_COLOR_NOCHANGE - 0x10;

	g_string_append_c(out, '%');
	g_string_append_c(out, bg ? 'x' : 'X');
	if (value > 214)
		value += 10;
	g_string_append_c(out, '1' + (value / 36));
	g_string_append_c(out, ext_color_al[value % 36]);
}

void unformat_24bit_color(char **ptr, int off, int *fgcolor, int *bgcolor, int *flags)
{
	unsigned int color;
	unsigned char rgbx[4];
	unsigned int i;
	for (i = 0; i < 4; ++i) {
		if ((*ptr)[i + off] == '\0')
			return;
		rgbx[i] = (*ptr)[i + off];
	}
	rgbx[3] -= 0x20;
	*ptr += 4;
	for (i = 0; i < 3; ++i) {
		if (rgbx[3] & (0x10 << i))
			rgbx[i] -= 0x20;
	}
	color = rgbx[0] << 16 | rgbx[1] << 8 | rgbx[2];
	if (rgbx[3] & 0x1) {
		*bgcolor = color;
		*flags |= GUI_PRINT_FLAG_COLOR_24_BG;
	} else {
		*fgcolor = color;
		*flags |= GUI_PRINT_FLAG_COLOR_24_FG;
	}
}

static void format_24bit_color_unexpand(GString *out, int off, const char **ptr)
{
	unsigned int color;
	unsigned char rgbx[4];
	unsigned int i;
	for (i = 0; i < 4; ++i) {
		if ((*ptr)[i + off] == '\0')
			return;
		rgbx[i] = (*ptr)[i + off];
	}
	rgbx[3] -= 0x20;
	*ptr += 4;
	g_string_append_c(out, '%');
	for (i = 0; i < 3; ++i) {
		if (rgbx[3] & (0x10 << i))
			rgbx[i] -= 0x20;
	}
	color = rgbx[0] << 16 | rgbx[1] << 8 | rgbx[2];
	g_string_append_c(out, rgbx[3] & 0x1 ? 'z' : 'Z');
	g_string_append_printf(out, "%06X", color);
}

void format_24bit_color(GString *out, int bg, unsigned int color)
{
	unsigned char rgb[] = { color >> 16, color >> 8, color };
	unsigned char x = bg ? 0x1 : 0;
	unsigned int i;
	g_string_append_c(out, 4);
	g_string_append_c(out, FORMAT_COLOR_24);
	for (i = 0; i < 3; ++i) {
		if (rgb[i] > 0x20)
			g_string_append_c(out, rgb[i]);
		else {
			g_string_append_c(out, 0x20 + rgb[i]);
			x |= 0x10 << i;
		}
	}
	g_string_append_c(out, 0x20 + x);
}

int format_expand_styles(GString *out, const char **format, int *flags)
{
	int retval = 1;

	char *p, fmt;

	/* storage for numerical parsing code for %x/X formats. */
	int tmp;
	unsigned int tmp2;

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
	case 'I':
		/* italic */
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_ITALIC);
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
		if ((*format)[0] == '\0')
			/* oops, reached end prematurely */
			(*format)--;

		break;
	case 'x':
	case 'X':
		if ((*format)[1] < '0' || (*format)[1] > '7')
			break;

		tmp = 16 + ((*format)[1] - '0' - 1) * 36;
		if (tmp > 231) {
			if (!isalpha((*format)[2]))
				break;

			tmp += (*format)[2] >= 'a' ? (*format)[2] - 'a' : (*format)[2] - 'A';

			if (tmp > 255)
				break;
		} else if (tmp > 0) {
			if (!isalnum((*format)[2]))
				break;

			if ((*format)[2] >= 'a')
				tmp += 10 + (*format)[2] - 'a';
			else if ((*format)[2] >= 'A')
				tmp += 10 + (*format)[2] - 'A';
			else
				tmp += (*format)[2] - '0';
		} else {
			if (!isxdigit((*format)[2]))
				break;

			tmp = g_ascii_xdigit_value((*format)[2]);
		}

		retval += 2;

		format_ext_color(out, fmt == 'x', tmp);
		break;
	case 'z':
	case 'Z':
		tmp2 = 0;
		for (tmp = 1; tmp < 7; ++tmp) {
			if (!isxdigit((*format)[tmp])) {
				tmp2 = UINT_MAX;
				break;
			}
			tmp2 <<= 4;
			tmp2 |= g_ascii_xdigit_value((*format)[tmp]);
		}

		if (tmp2 == UINT_MAX)
			break;

		retval += 6;

		format_24bit_color(out, fmt == 'z', tmp2);
		break;
	case 'o':
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
		g_string_append_c(out, (char) -1);
		break;
	case 'O':
		g_string_append_c(out, 4);
		g_string_append_c(out, (char) -1);
		g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
		break;
	default:
		/* check if it's a background color */
		p = strchr(format_backs, fmt);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			g_string_append_c(out, (char) ((int) (p - format_backs) + '0'));
			break;
		}

		/* check if it's a foreground color */
		if (fmt == 'p')
			fmt = 'm';
		p = strchr(format_fores, fmt);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, (char) ((int) (p - format_fores) + '0'));
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			break;
		}

		/* check if it's a bold foreground color */
		if (fmt == 'P')
			fmt = 'M';
		p = strchr(format_boldfores, fmt);
		if (p != NULL) {
			g_string_append_c(out, 4);
			g_string_append_c(out, (char) (8 + (int) (p - format_boldfores) + '0'));
			g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			break;
		}

		return FALSE;
	}

	return retval;
}

void format_read_arglist(va_list va, FORMAT_REC *format, char **arglist, int arglist_size,
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

			arglist[num] = buffer + bufpos;
			len = g_snprintf(buffer + bufpos, buffer_size - bufpos, "%d", d);
			bufpos += len + 1;
			break;
		}
		case FORMAT_LONG: {
			long l = (long) va_arg(va, long);

			if (bufpos >= buffer_size) {
				arglist[num] = "";
				break;
			}

			arglist[num] = buffer + bufpos;
			len = g_snprintf(buffer + bufpos, buffer_size - bufpos, "%ld", l);
			bufpos += len + 1;
			break;
		}
		case FORMAT_FLOAT: {
			double f = (double) va_arg(va, double);

			if (bufpos >= buffer_size) {
				arglist[num] = "";
				break;
			}

			arglist[num] = buffer + bufpos;
			len = g_snprintf(buffer + bufpos, buffer_size - bufpos, "%0.2f", f);
			bufpos += len + 1;
			break;
		}
		}
	}
}

void format_dest_meta_stash(TEXT_DEST_REC *dest, const char *meta_key, const char *meta_value)
{
	g_hash_table_replace(dest->meta, i_refstr_intern(meta_key), g_strdup(meta_value));
}

const char *format_dest_meta_stash_find(TEXT_DEST_REC *dest, const char *meta_key)
{
	return g_hash_table_lookup(dest->meta, meta_key);
}

void format_dest_meta_clear_all(TEXT_DEST_REC *dest)
{
	g_hash_table_remove_all(dest->meta);
}

static void clear_global_meta(WINDOW_REC *window, TEXT_DEST_REC *dest)
{
	if (dest != NULL && dest->meta == global_meta)
		g_hash_table_remove_all(global_meta);
}

void format_create_dest_tag_meta(TEXT_DEST_REC *dest, void *server, const char *server_tag,
                                 const char *target, int level, WINDOW_REC *window,
                                 GHashTable *meta)
{
	memset(dest, 0, sizeof(TEXT_DEST_REC));

	dest->server = server;
	dest->server_tag = server != NULL ? SERVER(server)->tag : server_tag;
	dest->target = target;
	dest->level = level;
	dest->window = window != NULL ? window : window_find_closest(server, target, level);
	dest->meta = meta != NULL ? meta : global_meta;
}

void format_create_dest_tag(TEXT_DEST_REC *dest, void *server, const char *server_tag,
                            const char *target, int level, WINDOW_REC *window)
{
	format_create_dest_tag_meta(dest, server, server_tag, target, level, window,
	                            server != NULL ? SERVER(server)->current_incoming_meta : NULL);
}

void format_create_dest(TEXT_DEST_REC *dest, void *server, const char *target, int level,
                        WINDOW_REC *window)
{
	format_create_dest_tag(dest, server, NULL, target, level, window);
}

/* Return length of text part in string (ie. without % codes) */
int format_get_length(const char *str)
{
	GString *tmp;
	int len;
	int utf8;
	int adv = 0;

	g_return_val_if_fail(str != NULL, 0);

	utf8 = string_policy(str);

	tmp = g_string_new(NULL);
	len = 0;
	while (*str != '\0') {
		if (*str == '%' && str[1] != '\0') {
			str++;
			if (*str != '%') {
				adv = format_expand_styles(tmp, &str, NULL);
				str += adv;
				if (adv)
					continue;
			}

			/* %% or unknown %code, written as-is */
			if (*str != '%')
				len++;
		}

		len += string_advance(&str, utf8);
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
	int utf8;
	int adv = 0;
	g_return_val_if_fail(str != NULL, 0);
	g_return_val_if_fail(len >= 0, 0);

	utf8 = string_policy(str);

	start = str;
	tmp = g_string_new(NULL);
	while (*str != '\0') {
		oldstr = str;
		if (*str == '%' && str[1] != '\0') {
			str++;
			if (*str != '%') {
				adv = format_expand_styles(tmp, &str, NULL);
				if (adv) {
					str += adv;
					continue;
				}
				/* discount for unknown % */
				if (--len < 0) {
					str = oldstr;
					break;
				}
				oldstr = str;
			}
		}

		len -= string_advance(&str, utf8);
		if (len < 0) {
			str = oldstr;
			break;
		}
	}

	g_string_free(tmp, TRUE);
	return (int) (str - start);
}

char *format_string_expand(const char *text, int *flags)
{
	GString *out;
	char code, *ret;
	int adv;

	g_return_val_if_fail(text != NULL, NULL);

	out = g_string_new(NULL);

	if (flags != NULL)
		*flags = 0;
	code = 0;
	while (*text != '\0') {
		if (code == '%') {
			/* color code */
			adv = format_expand_styles(out, &text, flags);
			if (!adv) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *text);
			} else {
				text += adv - 1;
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

	ret = g_string_free_and_steal(out);
	return ret;
}

inline static void format_flag_unexpand(GString *out, char flag)
{
	g_string_append_c(out, '%');
	g_string_append_c(out, flag);
}

char *format_string_unexpand(const char *text, int flags)
{
	GString *out;

	g_return_val_if_fail(text != NULL, NULL);

	out = g_string_sized_new(strlen(text));
	while (*text != '\0') {
		switch (*text) {
		case '%':
			g_string_append(out, "%%");
			break;
		case 4:
			text++;
			if (*text == '\0')
				break;
			switch (*text) {
			case FORMAT_COLOR_EXT1:
				format_ext_color_unexpand(out, FALSE, 0x10, *++text);
				break;
			case FORMAT_COLOR_EXT1_BG:
				format_ext_color_unexpand(out, TRUE, 0x10, *++text);
				break;
			case FORMAT_COLOR_EXT2:
				format_ext_color_unexpand(out, FALSE, 0x60, *++text);
				break;
			case FORMAT_COLOR_EXT2_BG:
				format_ext_color_unexpand(out, TRUE, 0x60, *++text);
				break;
			case FORMAT_COLOR_EXT3:
				format_ext_color_unexpand(out, FALSE, 0xb0, *++text);
				break;
			case FORMAT_COLOR_EXT3_BG:
				format_ext_color_unexpand(out, TRUE, 0xb0, *++text);
				break;
			case FORMAT_COLOR_24:
				format_24bit_color_unexpand(out, 1, &text);
				break;
			case FORMAT_STYLE_BLINK:
				format_flag_unexpand(out, 'F');
				break;
			case FORMAT_STYLE_UNDERLINE:
				format_flag_unexpand(out, 'U');
				break;
			case FORMAT_STYLE_BOLD:
				format_flag_unexpand(out, '9');
				break;
			case FORMAT_STYLE_REVERSE:
				format_flag_unexpand(out, '8');
				break;
			case FORMAT_STYLE_INDENT:
				format_flag_unexpand(out, '|');
				break;
			case FORMAT_STYLE_ITALIC:
				format_flag_unexpand(out, 'I');
				break;
			case FORMAT_STYLE_DEFAULTS:
				format_flag_unexpand(out, 'N');
				break;
			case FORMAT_STYLE_CLRTOEOL:
				format_flag_unexpand(out, '>');
				break;
			case FORMAT_STYLE_MONOSPACE:
				format_flag_unexpand(out, '#');
				break;
			default:
				if (*text != FORMAT_COLOR_NOCHANGE) {
					unsigned int value = (unsigned char) *text - '0';

					g_string_append_c(out, '%');
					if (value < 8) {
						g_string_append_c(out, format_fores[value]);
					} else if (value < 16) {
						g_string_append_c(out, format_boldfores[value - 8]);
					} else {
						g_string_append_c(out, 'O');
					}
				}
				text++;
				if (*text == '\0')
					break;

				if (*text != FORMAT_COLOR_NOCHANGE) {
					unsigned int value = (unsigned char) *text - '0';

					g_string_append_c(out, '%');
					if (value < 8) {
						g_string_append_c(out, format_backs[value]);
					} else if (value < 16) {
						g_string_append(out, "x0");
						g_string_append_c(out, ext_color_al[value]);
					} else {
						g_string_append_c(out, 'o');
					}
				}
				break;
			}
			break;
		default:
			g_string_append_c(out, *text);
			break;
		}
		if (*text != '\0')
			text++;
	}

	return g_string_free(out, FALSE);
}

static char *format_get_text_args(TEXT_DEST_REC *dest, const char *text, char **arglist)
{
	GString *out;
	char code, *ret;
	int need_free;
	int adv;

	out = g_string_new(NULL);

	code = 0;
	while (*text != '\0') {
		if (code == '%') {
			/* color code */
			adv = format_expand_styles(out, &text, &dest->flags);
			if (!adv) {
				g_string_append_c(out, '%');
				g_string_append_c(out, '%');
				g_string_append_c(out, *text);
			} else {
				text += adv - 1;
			}
			code = 0;
		} else if (code == '$') {
			/* argument */
			char *ret;

			ret = parse_special((char **) &text, dest->server,
			                    dest->target == NULL ?
			                        NULL :
			                        window_item_find(dest->server, dest->target),
			                    arglist, &need_free, NULL, 0);

			if (ret != NULL) {
				/* string shouldn't end with \003 or it could
				   mess up the next one or two characters */
				int diff;
				int len = strlen(ret);
				while (len > 0 && ret[len - 1] == 3)
					len--;
				diff = strlen(ret) - len;

				g_string_append(out, ret);
				if (diff > 0)
					g_string_truncate(out, out->len - diff);
				if (need_free)
					g_free(ret);
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

	ret = g_string_free_and_steal(out);
	return ret;
}

char *format_get_text_theme(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest,
                            int formatnum, ...)
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

char *format_get_text_theme_args(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest,
                                 int formatnum, va_list va)
{
	char *arglist[MAX_FORMAT_PARAMS];
	char buffer[DEFAULT_FORMAT_ARGLIST_SIZE];
	FORMAT_REC *formats;

	formats = g_hash_table_lookup(default_formats, module);
	format_read_arglist(va, &formats[formatnum], arglist, sizeof(arglist) / sizeof(char *),
	                    buffer, sizeof(buffer));

	return format_get_text_theme_charargs(theme, module, dest, formatnum, arglist);
}

/* Check if format number is a message format that needs nick column */
static gboolean is_message_format(int formatnum)
{
	/* Only apply to actual message formats, NOT timestamps or other formats */
	return (formatnum == TXT_OWN_MSG || formatnum == TXT_OWN_MSG_CHANNEL ||
	        formatnum == TXT_PUBMSG || formatnum == TXT_PUBMSG_CHANNEL ||
	        formatnum == TXT_PUBMSG_ME || formatnum == TXT_PUBMSG_ME_CHANNEL ||
	        formatnum == TXT_PUBMSG_HILIGHT || formatnum == TXT_PUBMSG_HILIGHT_CHANNEL);
}

/* Get nick parameter number for specific format */
static int get_nick_param_for_format(int formatnum)
{
	switch (formatnum) {
	case TXT_OWN_MSG:
	case TXT_OWN_MSG_CHANNEL:
	case TXT_PUBMSG:
	case TXT_PUBMSG_CHANNEL:
	case TXT_PUBMSG_ME:
	case TXT_PUBMSG_ME_CHANNEL:
		return 0; /* $0 = nick */

	case TXT_PUBMSG_HILIGHT:
	case TXT_PUBMSG_HILIGHT_CHANNEL:
		return 1; /* $1 = nick (because $0 = color) */

	default:
		return 0; /* fallback */
	}
}

/* Apply nick column formatting to format string */
static char *apply_nick_column_formatting(const char *format, int formatnum)
{
	char *result;
	char *pos, *before, *after;
	char search_param[10], replace_param[20];
	int nick_param;

	if (!format)
		return NULL;

	/* Get correct parameter number for nick in this format */
	nick_param = get_nick_param_for_format(formatnum);
	g_snprintf(search_param, sizeof(search_param), "${%d}", nick_param);
	g_snprintf(replace_param, sizeof(replace_param), "${nicktrunc}");

	/* Replace ${X} with ${nicktrunc} where X is the nick parameter */
	pos = strstr(format, search_param);
	if (pos) {
		before = g_strndup(format, pos - format);
		after = pos + strlen(search_param);
		result = g_strdup_printf("$nickalign%s%s%s", before, replace_param, after);
		g_free(before);
	} else {
		/* No replacement needed, just add nickalign */
		result = g_strdup_printf("$nickalign%s", format);
	}

	return result;
}

char *format_get_text_theme_charargs(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest,
                                     int formatnum, char **args)
{
	MODULE_THEME_REC *module_theme;
	char *text, *modified_text = NULL;
	char *result;

	if (module == NULL)
		return NULL;

	module_theme = g_hash_table_lookup(theme->modules, module);
	if (module_theme == NULL)
		return NULL;

	text = module_theme->expanded_formats[formatnum];

	/* Apply nick column formatting if enabled and this is a message format */
	/* Additional protection: avoid recursion during timestamp formatting */
	if (settings_get_bool("nick_column_enabled") && g_strcmp0(module, "fe-common/core") == 0 &&
	    is_message_format(formatnum) && nick_formatting_depth == 0) { /* Prevent recursion */

		nick_formatting_depth++;
		modified_text = apply_nick_column_formatting(text, formatnum);
		text = modified_text;
		nick_formatting_depth--;
	}

	result = format_get_text_args(dest, text, args);

	if (modified_text)
		g_free(modified_text);

	return result;
}

char *format_get_text(const char *module, WINDOW_REC *window, void *server, const char *target,
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

	ret = g_string_free_and_steal(str);
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

	ret = g_string_free_and_steal(str);
	return ret;
}

#define LINE_START_IRSSI_LEVEL (MSGLEVEL_CLIENTERROR | MSGLEVEL_CLIENTNOTICE)

#define NOT_LINE_START_LEVEL                                                                       \
	(MSGLEVEL_NEVER | MSGLEVEL_LASTLOG | MSGLEVEL_CLIENTCRAP | MSGLEVEL_MSGS |                 \
	 MSGLEVEL_PUBLIC | MSGLEVEL_DCC | MSGLEVEL_DCCMSGS | MSGLEVEL_ACTIONS | MSGLEVEL_NOTICES | \
	 MSGLEVEL_PUBNOTICES | MSGLEVEL_SNOTES | MSGLEVEL_CTCPS)

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
	    (dest->level & (MSGLEVEL_NEVER | MSGLEVEL_LASTLOG)) != 0)
		return NULL;

	if (timestamp_timeout > 0) {
		diff = t - dest->window->last_timestamp;
		dest->window->last_timestamp = t;
		if (diff < timestamp_timeout)
			return NULL;
	}

	tm = localtime(&t);
	format = format_get_text_theme(theme, MODULE_NAME, dest, TXT_TIMESTAMP);
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
		if (dest->window->active != NULL && dest->window->active->server == dest->server)
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

	return format_get_text_theme(theme, MODULE_NAME, dest, TXT_SERVERTAG, dest->server_tag);
}

char *format_get_line_start(THEME_REC *theme, TEXT_DEST_REC *dest, time_t t)
{
	char *timestamp, *servertag;
	char *linestart;

	timestamp = get_timestamp(theme, dest, t);
	servertag = get_server_tag(theme, dest);

	if (timestamp == NULL && servertag == NULL)
		return NULL;

	linestart = g_strconcat(timestamp != NULL ? timestamp : "", servertag, NULL);

	g_free_not_null(timestamp);
	g_free_not_null(servertag);
	return linestart;
}

void format_newline(TEXT_DEST_REC *dest)
{
	g_return_if_fail(dest != NULL);
	g_return_if_fail(dest->window != NULL);

	signal_emit_id(signal_gui_print_text, 6, dest->window, GINT_TO_POINTER(-1),
	               GINT_TO_POINTER(-1), GINT_TO_POINTER(GUI_PRINT_FLAG_NEWLINE), "", dest);
}

/* parse ANSI color string */
static const char *get_ansi_color(THEME_REC *theme, const char *str, int *fg_ret, int *bg_ret,
                                  int *flags_ret)
{
	static char ansitab[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	const char *start;
	char *endptr;
	int fg, bg, flags, i;
	guint num, num2;

	if (*str != '[')
		return str;
	start = str++;

	fg = fg_ret == NULL || *fg_ret < 0 ? theme->default_color : *fg_ret;
	bg = bg_ret == NULL || *bg_ret < 0 ? -1 : *bg_ret;
	flags = flags_ret == NULL ? 0 : *flags_ret;

	num = 0;
	for (;; str++) {
		if (*str == '\0')
			return start;

		if (i_isdigit(*str)) {
			if (!parse_uint(str, &endptr, 10, &num)) {
				return start;
			}
			str = endptr;
		}

		if (*str != ';' && *str != 'm')
			return start;

		switch (num) {
		case 0:
			/* reset colors and attributes back to default */
			fg = theme->default_color;
			bg = -1;
			flags &= ~(GUI_PRINT_FLAG_INDENT | GUI_PRINT_FLAG_BOLD |
			           GUI_PRINT_FLAG_ITALIC | GUI_PRINT_FLAG_UNDERLINE |
			           GUI_PRINT_FLAG_BLINK | GUI_PRINT_FLAG_REVERSE |
			           GUI_PRINT_FLAG_COLOR_24_FG | GUI_PRINT_FLAG_COLOR_24_BG);
			break;
		case 1:
			/* hilight */
			flags |= GUI_PRINT_FLAG_BOLD;
			break;
		case 22:
			/* normal */
			flags &= ~GUI_PRINT_FLAG_BOLD;
			break;
		case 3:
			/* italic */
			flags |= GUI_PRINT_FLAG_ITALIC;
			break;
		case 23:
			/* not italic */
			flags &= ~GUI_PRINT_FLAG_ITALIC;
			break;
		case 4:
			/* underline */
			flags |= GUI_PRINT_FLAG_UNDERLINE;
			break;
		case 24:
			/* not underline */
			flags &= ~GUI_PRINT_FLAG_UNDERLINE;
			break;
		case 5:
			/* blink */
			flags |= GUI_PRINT_FLAG_BLINK;
			break;
		case 25:
			/* steady */
			flags &= ~GUI_PRINT_FLAG_BLINK;
			break;
		case 7:
			/* reverse */
			flags |= GUI_PRINT_FLAG_REVERSE;
			break;
		case 27:
			/* positive */
			flags &= ~GUI_PRINT_FLAG_REVERSE;
			break;
		case 39:
			/* reset fg */
			flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
			fg = theme->default_color;
			break;
		case 49:
			/* reset bg */
			bg = -1;
			flags &= ~(GUI_PRINT_FLAG_COLOR_24_BG | GUI_PRINT_FLAG_INDENT);
			break;
		case 38:
		case 48:
			/* ANSI indexed color or RGB color */
			if (*str != ';')
				break;
			str++;

			if (!parse_uint(str, &endptr, 10, &num2)) {
				return start;
			}
			str = endptr;

			if (*str == '\0')
				return start;

			switch (num2) {
			case 2:
				/* RGB */
				num2 = 0;

				for (i = 0; i < 3; ++i) {
					num2 <<= 8;

					if (*str != ';' && *str != ':') {
						i = -1;
						break;
					}
					str++;
					for (; i_isdigit(*str); str++)
						num2 = (num2 & ~0xff) |
						       (((num2 & 0xff) * 10 + (*str - '0')) & 0xff);

					if (*str == '\0')
						return start;
				}

				if (i == -1)
					break;

				if (num == 38) {
					flags |= GUI_PRINT_FLAG_COLOR_24_FG;
					fg = num2;
				} else if (num == 48) {
					flags |= GUI_PRINT_FLAG_COLOR_24_BG;
					bg = num2;
				}

				break;
			case 5:
				/* indexed */
				if (*str != ';')
					break;
				str++;

				if (!parse_uint(str, &endptr, 10, &num2)) {
					return start;
				}
				str = endptr;

				if (*str == '\0')
					return start;

				if (num == 38) {
					flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
					fg = num2;
				} else if (num == 48) {
					flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
					bg = num2;
				}

				break;
			}
			break;
		default:
			if (num >= 30 && num <= 37) {
				flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
				fg = ansitab[num - 30];
			} else if (num >= 40 && num <= 47) {
				flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
				bg = ansitab[num - 40];
			} else if (num >= 90 && num <= 97) {
				flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
				fg = 8 + ansitab[num - 90];
			} else if (num >= 100 && num <= 107) {
				flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
				bg = 8 + ansitab[num - 100];
			}
			break;
		}
		num = 0;

		if (*str == 'm') {
			if (fg_ret != NULL)
				*fg_ret = fg;
			if (bg_ret != NULL)
				*bg_ret = bg;
			if (flags_ret != NULL)
				*flags_ret = flags;

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

	if (!i_isdigit(**str)) {
		/* turn off color */
		fg = -1;
		bg = -1;
	} else {
		/* foreground color */
		fg = **str - '0';
		(*str)++;
		if (i_isdigit(**str)) {
			fg = fg * 10 + (**str - '0');
			(*str)++;
		}

		if ((*str)[0] == ',' && i_isdigit((*str)[1])) {
			/* background color */
			(*str)++;
			bg = **str - '0';
			(*str)++;
			if (i_isdigit(**str)) {
				bg = bg * 10 + (**str - '0');
				(*str)++;
			}
		}
	}

	if (fg_ret)
		*fg_ret = fg;
	if (bg_ret)
		*bg_ret = bg;
}

#define IS_COLOR_CODE(c)                                                                           \
	((c) == 2 || (c) == 3 || (c) == 4 || (c) == 6 || (c) == 7 || (c) == 15 || (c) == 17 ||     \
	 (c) == 22 || (c) == 27 || (c) == 29 || (c) == 31)

/* Return how many characters in `str' must be skipped before `len'
   characters of text is skipped. */
int strip_real_length(const char *str, int len, int *last_color_pos, int *last_color_len)
{
	const char *start = str;

	if (last_color_pos != NULL)
		*last_color_pos = -1;
	if (last_color_len != NULL)
		*last_color_len = -1;

	while (*str != '\0') {
		if (*str == 3) { /* mIRC color */
			const char *mircstart = str;

			if (last_color_pos != NULL)
				*last_color_pos = (int) (str - start);
			str++;
			get_mirc_color(&str, NULL, NULL);
			if (last_color_len != NULL)
				*last_color_len = (int) (str - mircstart);

		} else if (*str == 4 && str[1] != '\0') {
			/* We expect 4 to indicate an internal Irssi color code. However 4
			 * also means hex color, an alternative to mIRC color codes. We
			 * don't support those. */
			if (str[1] == FORMAT_COLOR_24 && str[2] != '\0') {
				if (str[3] == '\0')
					str++;
				else if (str[4] == '\0')
					str += 2;
				else if (str[5] == '\0')
					str += 3;
				else {
					if (last_color_pos != NULL)
						*last_color_pos = (int) (str - start);
					if (last_color_len != NULL)
						*last_color_len = 6;
					str += 4;
				}
			} else if (str[1] < FORMAT_STYLE_SPECIAL && str[2] != '\0') {
				if (last_color_pos != NULL)
					*last_color_pos = (int) (str - start);
				if (last_color_len != NULL)
					*last_color_len = 3;
				str++;
			} else if (str[1] == FORMAT_STYLE_DEFAULTS) {
				if (last_color_pos != NULL)
					*last_color_pos = (int) (str - start);
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

	return (int) (str - start);
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
				if (p[1] == FORMAT_COLOR_24) {
					if (p[3] == '\0')
						p += 2;
					else if (p[4] == '\0')
						p += 3;
					else if (p[5] == '\0')
						p += 4;
					else
						p += 5;
				} else
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

/* parse text string into GUI_PRINT_FLAG_* separated pieces and emit them to handler
   handler is a SIGNAL_FUNC with the following arguments:

   WINDOW_REC *window, void *fgcolor_int, void *bgcolor_int,
       void *flags_int, const char *textpiece, TEXT_DEST_REC *dest

 */
void format_send_as_gui_flags(TEXT_DEST_REC *dest, const char *text, SIGNAL_FUNC handler)
{
	THEME_REC *theme;
	char *dup, *str, *ptr, type;
	int fgcolor, bgcolor;
	int flags;

	theme = window_get_theme(dest->window);

	dup = str = g_strdup(text);

	flags = 0;
	fgcolor = theme->default_color;
	bgcolor = -1;

	if (*str == '\0') {
		/* empty line, write line info only */
		handler(dest->window, GINT_TO_POINTER(fgcolor), GINT_TO_POINTER(bgcolor),
		        GINT_TO_POINTER(flags), str, dest);
	}

	while (*str != '\0') {
		type = '\0';
		for (ptr = str; *ptr != '\0'; ptr++) {
			if (IS_COLOR_CODE(*ptr) || *ptr == '\n') {
				type = *ptr;
				*ptr++ = '\0';
				break;
			}
		}

		if (type == 4 && *ptr == FORMAT_STYLE_CLRTOEOL) {
			/* clear to end of line */
			flags |= GUI_PRINT_FLAG_CLRTOEOL;
		}

		if (*str != '\0' || (flags & GUI_PRINT_FLAG_CLRTOEOL)) {
			/* send the text to gui handler */
			handler(dest->window, GINT_TO_POINTER(fgcolor), GINT_TO_POINTER(bgcolor),
			        GINT_TO_POINTER(flags), str, dest);
			flags &= ~(GUI_PRINT_FLAG_INDENT | GUI_PRINT_FLAG_CLRTOEOL);
		}

		if (type == '\n') {
			handler(dest->window, GINT_TO_POINTER(-1), GINT_TO_POINTER(-1),
			        GINT_TO_POINTER(GUI_PRINT_FLAG_NEWLINE), "", dest);
			fgcolor = theme->default_color;
			bgcolor = -1;
			flags &= GUI_PRINT_FLAG_INDENT | GUI_PRINT_FLAG_MONOSPACE;
		}

		if (*ptr == '\0')
			break;

		switch (type) {
		case 2:
			/* bold */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_BOLD;
			break;
		case 3:
			/* MIRC color */
			get_mirc_color((const char **) &ptr, hide_colors ? NULL : &fgcolor,
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
			case FORMAT_STYLE_ITALIC:
				flags ^= GUI_PRINT_FLAG_ITALIC;
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
				flags &= GUI_PRINT_FLAG_INDENT | GUI_PRINT_FLAG_MONOSPACE;
				break;
			case FORMAT_STYLE_CLRTOEOL:
				break;
			case FORMAT_COLOR_EXT1:
				fgcolor = 0x10 + *++ptr - FORMAT_COLOR_NOCHANGE;
				flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
				break;
			case FORMAT_COLOR_EXT1_BG:
				bgcolor = 0x10 + *++ptr - FORMAT_COLOR_NOCHANGE;
				flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
				break;
			case FORMAT_COLOR_EXT2:
				fgcolor = 0x60 + *++ptr - FORMAT_COLOR_NOCHANGE;
				flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
				break;
			case FORMAT_COLOR_EXT2_BG:
				bgcolor = 0x60 + *++ptr - FORMAT_COLOR_NOCHANGE;
				flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
				break;
			case FORMAT_COLOR_EXT3:
				fgcolor = 0xb0 + *++ptr - FORMAT_COLOR_NOCHANGE;
				flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
				break;
			case FORMAT_COLOR_EXT3_BG:
				bgcolor = 0xb0 + *++ptr - FORMAT_COLOR_NOCHANGE;
				flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
				break;
			case FORMAT_COLOR_24:
				unformat_24bit_color(&ptr, 1, &fgcolor, &bgcolor, &flags);
				break;
			default:
				if (*ptr != FORMAT_COLOR_NOCHANGE) {
					flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
					fgcolor =
					    *ptr == (char) 0xff ? -1 : (unsigned char) *ptr - '0';
				}
				if (ptr[1] == '\0')
					break;

				ptr++;
				if (*ptr != FORMAT_COLOR_NOCHANGE) {
					flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
					bgcolor = *ptr == (char) 0xff ? -1 : *ptr - '0';
				}
			}
			if (*ptr == '\0')
				break;

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
			flags &= GUI_PRINT_FLAG_INDENT | GUI_PRINT_FLAG_MONOSPACE;
			break;
		case 17:
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_MONOSPACE;
			break;
		case 22:
			/* reverse */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_REVERSE;
			break;
		case 29:
			/* italic */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_ITALIC;
			break;
		case 31:
			/* underline */
			if (!hide_text_style)
				flags ^= GUI_PRINT_FLAG_UNDERLINE;
			break;
		case 27:
			/* ansi color code */
			ptr = (char *) get_ansi_color(theme, ptr, hide_colors ? NULL : &fgcolor,
			                              hide_colors ? NULL : &bgcolor,
			                              hide_colors ? NULL : &flags);
			break;
		}

		str = ptr;
	}

	g_free(dup);
}

inline static void gui_print_text_emitter(WINDOW_REC *window, void *fgcolor_int, void *bgcolor_int,
                                          void *flags_int, const char *textpiece,
                                          TEXT_DEST_REC *dest)
{
	signal_emit_id(signal_gui_print_text, 6, window, fgcolor_int, bgcolor_int, flags_int,
	               textpiece, dest);
}

/* send a fully parsed text string for GUI to print */
void format_send_to_gui(TEXT_DEST_REC *dest, const char *text)
{
	format_send_as_gui_flags(dest, text, (SIGNAL_FUNC) gui_print_text_emitter);
}

void format_gui_flags(GString *out, int *last_fg, int *last_bg, int *last_flags, int fg, int bg,
                      int flags)
{
	if (fg != *last_fg ||
	    (flags & GUI_PRINT_FLAG_COLOR_24_FG) != (*last_flags & GUI_PRINT_FLAG_COLOR_24_FG)) {
		*last_fg = fg;

		if (flags & GUI_PRINT_FLAG_COLOR_24_FG) {
			*last_flags |= GUI_PRINT_FLAG_COLOR_24_FG;
			format_24bit_color(out, 0, fg);
		} else {
			*last_flags &= ~GUI_PRINT_FLAG_COLOR_24_FG;
			if (fg < 0) {
				g_string_append_c(out, 4);
				g_string_append_c(out, (char) -1);
				g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
			} else {
				format_ext_color(out, 0, fg);
			}
		}
	}
	if (bg != *last_bg ||
	    (flags & GUI_PRINT_FLAG_COLOR_24_BG) != (*last_flags & GUI_PRINT_FLAG_COLOR_24_BG)) {
		*last_bg = bg;
		if (flags & GUI_PRINT_FLAG_COLOR_24_BG) {
			*last_flags |= GUI_PRINT_FLAG_COLOR_24_BG;
			format_24bit_color(out, 1, bg);
		} else {
			*last_flags &= ~GUI_PRINT_FLAG_COLOR_24_BG;
			if (bg < 0) {
				g_string_append_c(out, 4);
				g_string_append_c(out, FORMAT_COLOR_NOCHANGE);
				g_string_append_c(out, (char) -1);
			} else {
				format_ext_color(out, 1, bg);
			}
		}
	}

	if ((flags & GUI_PRINT_FLAG_UNDERLINE) != (*last_flags & GUI_PRINT_FLAG_UNDERLINE)) {
		*last_flags ^= GUI_PRINT_FLAG_UNDERLINE;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_UNDERLINE);
	}
	if ((flags & GUI_PRINT_FLAG_REVERSE) != (*last_flags & GUI_PRINT_FLAG_REVERSE)) {
		*last_flags ^= GUI_PRINT_FLAG_REVERSE;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_REVERSE);
	}
	if ((flags & GUI_PRINT_FLAG_BLINK) != (*last_flags & GUI_PRINT_FLAG_BLINK)) {
		*last_flags ^= GUI_PRINT_FLAG_BLINK;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_BLINK);
	}
	if ((flags & GUI_PRINT_FLAG_BOLD) != (*last_flags & GUI_PRINT_FLAG_BOLD)) {
		*last_flags ^= GUI_PRINT_FLAG_BOLD;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_BOLD);
	}
	if ((flags & GUI_PRINT_FLAG_ITALIC) != (*last_flags & GUI_PRINT_FLAG_ITALIC)) {
		*last_flags ^= GUI_PRINT_FLAG_ITALIC;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_ITALIC);
	}
	if ((flags & GUI_PRINT_FLAG_MONOSPACE) != (*last_flags & GUI_PRINT_FLAG_MONOSPACE)) {
		*last_flags ^= GUI_PRINT_FLAG_MONOSPACE;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_MONOSPACE);
	}
	if (flags & GUI_PRINT_FLAG_INDENT) {
		*last_flags ^= GUI_PRINT_FLAG_INDENT;
		g_string_append_c(out, 4);
		g_string_append_c(out, FORMAT_STYLE_INDENT);
	}
}

static void read_settings(void)
{
	timestamp_level = settings_get_bool("timestamps") ? MSGLEVEL_ALL : 0;
	if (timestamp_level > 0)
		timestamp_level = settings_get_level("timestamp_level");
	timestamp_timeout = settings_get_time("timestamp_timeout") / 1000;

	hide_server_tags = settings_get_bool("hide_server_tags");
	hide_text_style = settings_get_bool("hide_text_style");
	hide_colors = hide_text_style || settings_get_bool("hide_colors");
}

void formats_init(void)
{
	signal_gui_print_text = signal_get_uniq_id("gui print text");
	global_meta =
	    g_hash_table_new_full(g_str_hash, (GEqualFunc) g_str_equal,
	                          (GDestroyNotify) i_refstr_release, (GDestroyNotify) g_free);

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add_last("gui print text finished", (SIGNAL_FUNC) clear_global_meta);
}

void formats_deinit(void)
{
	g_hash_table_destroy(global_meta);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("gui print text finished", (SIGNAL_FUNC) clear_global_meta);
}
