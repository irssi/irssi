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
#include "settings.h"
#include "servers.h"
#include "signals.h"
#include "lib-config/iconfig.h"
#include "misc.h"

static gboolean recode_get_charset(const char **charset)
{
	*charset = settings_get_str("term_charset");
	if (**charset)
		/* we use the same test as in src/fe-text/term.c:123 */
		return (g_strcasecmp(*charset, "utf-8") == 0);

	return g_get_charset(charset);
}

gboolean is_utf8(void)
{
	const char *charset;

	return recode_get_charset(&charset);
}

static gboolean is_translit(const char *charset)
{
	char *pos;

	pos = stristr(charset, "//translit");
	return (pos != NULL);
}

gboolean is_valid_charset(const char *charset)
{
	const char *from="UTF-8";
	const char *str="irssi";
	char *recoded, *to = NULL;
	gboolean valid;

	if (!charset || *charset == '\0')
		return FALSE;

	if (settings_get_bool("recode_transliterate") && !is_translit(charset))
		charset = to = g_strconcat(charset, "//TRANSLIT", NULL);

	recoded = g_convert(str, strlen(str), charset, from, NULL, NULL, NULL);
	valid = (recoded != NULL);
	g_free(recoded);
	g_free(to);
	return valid;
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

char *recode_in(const SERVER_REC *server, const char *str, const char *target)
{
	const char *from = NULL;
	const char *to = NULL;
	char *translit_to = NULL;
	char *recoded = NULL;
	gboolean term_is_utf8, str_is_utf8, translit, recode, autodetect;
	int len;
	int i;

	if (!str)
		return NULL;

	recode = settings_get_bool("recode");
	if (!recode)
		return g_strdup(str);

	len = strlen(str);

	/* Only validate for UTF-8 if an 8-bit encoding. */
	str_is_utf8 = 0;
	for (i = 0; i < len; ++i) {
		if (str[i] & 0x80) {
			str_is_utf8 = g_utf8_validate(str, len, NULL);
			break;
		}
	}
	translit = settings_get_bool("recode_transliterate");
	autodetect = settings_get_bool("recode_autodetect_utf8");
	term_is_utf8 = recode_get_charset(&to);

	if (autodetect && str_is_utf8)
		if (term_is_utf8)
			return g_strdup(str);
		else
			from = "UTF-8";
			
	else {
		from = find_conversion(server, target);
	}

	if (translit && !is_translit(to))
		to = translit_to = g_strconcat(to, "//TRANSLIT", NULL);
		
	if (from)
		recoded = g_convert_with_fallback(str, len, to, from, NULL, NULL, NULL, NULL);

	if (!recoded) {
		if (term_is_utf8) {
			if (!str_is_utf8)
				from = settings_get_str("recode_fallback");

		} else if (str_is_utf8)
			from = "UTF-8";

		if (from)
			recoded = g_convert_with_fallback(str, len, to, from, NULL, NULL, NULL, NULL);

		if (!recoded)
			recoded = g_strdup(str);
	}
	g_free(translit_to);
	return recoded;
}

char *recode_out(const SERVER_REC *server, const char *str, const char *target)
{
	char *recoded = NULL;
	const char *from = NULL;
	const char *to = NULL;
	char *translit_to = NULL;
	gboolean translit, term_is_utf8, recode;
	int len;

	if (!str)
		return NULL;

	recode = settings_get_bool("recode");
	if (!recode)
		return g_strdup(str);

	len = strlen(str);

	translit = settings_get_bool("recode_transliterate");

	to = find_conversion(server, target);
	if (to == NULL)
		/* default outgoing charset if set */
		to = settings_get_str("recode_out_default_charset");

	if (to && *to != '\0') {
		if (translit && !is_translit(to))
			to = translit_to = g_strconcat(to ,"//TRANSLIT", NULL);

		term_is_utf8 = recode_get_charset(&from);
		recoded = g_convert(str, len, to, from, NULL, NULL, NULL);
	}
	g_free(translit_to);
	if (!recoded)
		recoded = g_strdup(str);

	return recoded;
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

}
