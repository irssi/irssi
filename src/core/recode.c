/*
 recode.c : irssi

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
#include <irssi/src/core/settings.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/misc.h>

static char *translit_charset;
static gboolean term_is_utf8;

gboolean is_utf8(void)
{
	return term_is_utf8;
}

static gboolean is_translit(const char *charset)
{
	char *pos;

	pos = stristr(charset, "//translit");
	return (pos != NULL);
}

gboolean is_valid_charset(const char *charset)
{
	GIConv cd;
	char *to = NULL;

	if (!charset || *charset == '\0')
		return FALSE;

	if (settings_get_bool("recode_transliterate") && !is_translit(charset))
		charset = to = g_strconcat(charset, "//TRANSLIT", NULL);

	cd = g_iconv_open(charset, "UTF-8");
	g_free(to);
	if (cd != (GIConv)-1) {
		g_iconv_close(cd);
		return TRUE;
	}
	return FALSE;
}

static char *find_conversion(const SERVER_REC *server, const char *target)
{
	char *conv = NULL;

	if (server != NULL && target != NULL) {
		char *tagtarget = g_strdup_printf("%s/%s", server->tag, target);
		conv = iconfig_get_str("conversions", tagtarget, NULL);
		g_free(tagtarget);
	}
	if (conv == NULL && target != NULL)
		conv = iconfig_get_str("conversions", target, NULL);
	if (conv == NULL && server != NULL)
		conv = iconfig_get_str("conversions", server->tag, NULL);
	return conv;
}

static int str_is_ascii(const char *str)
{
	int i;

	for (i = 0; str[i] != '\0'; i++)
		if (str[i] & 0x80)
			return 0;
	return 1;
}

char *recode_in(const SERVER_REC *server, const char *str, const char *target)
{
	const char *from = NULL;
	const char *to = translit_charset;
	char *recoded = NULL;
	gboolean str_is_utf8, recode, autodetect;
	int len;

	if (!str)
		return NULL;

	recode = settings_get_bool("recode");
	if (!recode)
		return g_strdup(str);

	len = strlen(str);

	/* Only validate for UTF-8 if an 8-bit encoding. */
	str_is_utf8 = 0;
	if (!str_is_ascii(str))
		str_is_utf8 = g_utf8_validate(str, len, NULL);
	else if (!strchr(str, '\e'))
		str_is_utf8 = 1;
	autodetect = settings_get_bool("recode_autodetect_utf8");

	if (autodetect && str_is_utf8)
		if (term_is_utf8)
			return g_strdup(str);
		else
			from = "UTF-8";
	else
		from = find_conversion(server, target);

	/* Don't use TRANSLIT when both terminal and string are UTF-8
	 * and no specific conversion is configured - preserves emoji variation selectors */
	if (from == NULL && term_is_utf8 && str_is_utf8) {
		g_debug("recode_in: UTF-8 bypass for: %s", str);
		return g_strdup(str);
	}

	if (from)
		recoded = g_convert_with_fallback(str, len, to, from, NULL, NULL, NULL, NULL);

	if (!recoded) {
		if (str_is_utf8)
			if (term_is_utf8)
				return g_strdup(str);
			else
				from = "UTF-8";
		else
			if (term_is_utf8)
				from = settings_get_str("recode_fallback");
			else
				from = NULL;

		if (from)
			recoded = g_convert_with_fallback(str, len, to, from, NULL, NULL, NULL, NULL);

		if (!recoded)
			recoded = g_strdup(str);
	}
	return recoded;
}

char *recode_out(const SERVER_REC *server, const char *str, const char *target)
{
	char *recoded = NULL;
	const char *from = translit_charset;
	const char *to = NULL;
	char *translit_to = NULL;
	gboolean translit, recode, str_is_utf8;
	int len;

	if (!str)
		return NULL;

	recode = settings_get_bool("recode");
	if (!recode)
		return g_strdup(str);

	len = strlen(str);

	/* Check if string is valid UTF-8 */
	str_is_utf8 = g_utf8_validate(str, len, NULL);

	translit = settings_get_bool("recode_transliterate");

	to = find_conversion(server, target);
	if (to == NULL)
		/* default outgoing charset if set */
		to = settings_get_str("recode_out_default_charset");

	if (to && *to != '\0') {
		/* Don't use TRANSLIT when both terminal and target are UTF-8
		 * and string is valid UTF-8 - this preserves emoji variation selectors */
		if (translit && !is_translit(to) &&
		    !(term_is_utf8 && str_is_utf8 && g_ascii_strcasecmp(to, "UTF-8") == 0))
			to = translit_to = g_strconcat(to ,"//TRANSLIT", NULL);

		recoded = g_convert(str, len, to, from, NULL, NULL, NULL);
	} else if (term_is_utf8 && str_is_utf8) {
		/* When no specific charset conversion is configured and both terminal
		 * and string are UTF-8, don't do any conversion to preserve emoji */
		g_debug("recode_out: UTF-8 bypass for: %s", str);
		recoded = g_strdup(str);
	}
	g_free(translit_to);
	if (!recoded)
		recoded = g_strdup(str);

	return recoded;
}

char **recode_split(const SERVER_REC *server, const char *str,
		    const char *target, int len, gboolean onspace)
{
	GIConv cd = (GIConv)-1;
	const char *from = translit_charset;
	const char *to = translit_charset;
	char *translit_to = NULL;
	const char *inbuf = str;
	const char *previnbuf = inbuf;
	char *tmp = NULL;
	char *outbuf;
	gsize inbytesleft = strlen(inbuf);
	gsize outbytesleft = len;
	int n = 0;
	char **ret;

	g_warn_if_fail(str != NULL);
	if (str == NULL) {
		ret = g_new(char *, 1);
		ret[0] = NULL;
		return ret;
	}

	if (settings_get_bool("recode")) {
		to = find_conversion(server, target);
		if (to == NULL)
			/* default outgoing charset if set */
			to = settings_get_str("recode_out_default_charset");
		if (to != NULL && *to != '\0') {
			if (settings_get_bool("recode_transliterate") &&
			    !is_translit(to))
				to = translit_to = g_strconcat(to,
							       "//TRANSLIT",
							       NULL);
		} else {
			to = from;
		}
	}

	cd = g_iconv_open(to, from);
	if (cd == (GIConv)-1) {
		/* Fall back to splitting by byte. */
		ret = strsplit_len(str, len, onspace);
		goto out;
	}

	tmp = g_malloc(outbytesleft);
	outbuf = tmp;
	ret = g_new(char *, 1);
	while (g_iconv(cd, (char **)&inbuf, &inbytesleft, &outbuf,
		       &outbytesleft) == -1) {
		if (errno != E2BIG) {
			/*
			 * Conversion failed. Fall back to splitting
			 * by byte.
			 */
			ret[n] = NULL;
			g_strfreev(ret);
			ret = strsplit_len(str, len, onspace);
			goto out;
		}

		/* Outbuf overflowed, split the input string. */
		if (onspace) {
			/*
			 * Try to find a space to split on and leave
			 * the space on the previous line.
			 */
			int i;
			for (i = 0; i < inbuf - previnbuf; i++) {
				if (previnbuf[inbuf-previnbuf-1-i] == ' ') {
					inbuf -= i;
					inbytesleft += i;
					break;
				}
			}
		}
		ret[n++] = g_strndup(previnbuf, inbuf - previnbuf);
		ret = g_renew(char *, ret, n + 1);
		previnbuf = inbuf;

		/* Reset outbuf for the next substring. */
		outbuf = tmp;
		outbytesleft = len;
	}
	/* Copy the last substring into the array. */
	ret[n++] = g_strndup(previnbuf, inbuf - previnbuf);
	ret = g_renew(char *, ret, n + 1);
	ret[n] = NULL;

out:
	if (cd != (GIConv)-1)
		g_iconv_close(cd);
	g_free(translit_to);
	g_free(tmp);

	return ret;
}

void recode_update_charset(void)
{
	const char *charset = settings_get_str("term_charset");
	term_is_utf8 = !g_ascii_strcasecmp(charset, "UTF-8");
	g_free(translit_charset);
	if (settings_get_bool("recode_transliterate") && !is_translit(charset))
		translit_charset = g_strconcat(charset, "//TRANSLIT", NULL);
	else
		translit_charset = g_strdup(charset);
}

void recode_init(void)
{
	settings_add_bool("misc", "recode", TRUE);
	settings_add_str("misc", "recode_fallback", "CP1252");
	settings_add_str("misc", "recode_out_default_charset", "");
	settings_add_bool("misc", "recode_transliterate", TRUE);
	settings_add_bool("misc", "recode_autodetect_utf8", TRUE);
}

void recode_deinit(void)
{
	g_free(translit_charset);
}
