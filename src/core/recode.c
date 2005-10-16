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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "settings.h"
#include "servers.h"
#include "signals.h"
#include "lib-config/iconfig.h"
#include "misc.h"

#ifdef HAVE_GLIB2
static gboolean recode_get_charset(const char **charset)
{
	*charset = settings_get_str("term_charset");
	if (**charset)
		/* we use the same test as in src/fe-text/term.c:123 */
			return !g_strcasecmp(*charset, "utf-8");

	return g_get_charset(charset);
}
#endif

gboolean is_valid_charset(const char *charset)
{
#ifdef HAVE_GLIB2
	const char *from="UTF-8";
	const char *str="irssi";
	char *recoded;
	gboolean valid;

	if (!charset || *charset == '\0')
		return FALSE;
	recoded = g_convert(str, strlen(str), charset, from, NULL, NULL, NULL);
	valid = (recoded != NULL);
	g_free(recoded);
	return valid;
#else
	if (!charset || *charset =='\0')
		return FALSE;
	return TRUE;
#endif
}

static gboolean is_translit(const char *charset)
{
	char *pos;
	pos = stristr(charset, "//translit");
	return (pos != NULL);
}

char *recode_in(const SERVER_REC *server, const char *str, const char *target)
{
#ifdef HAVE_GLIB2
	const char *from = NULL;
	const char *to = NULL;
	char *translit_to = NULL;
	char *recoded = NULL;
	char *tagtarget = NULL;
	gboolean term_is_utf8, str_is_utf8, translit, recode;
	int len;

	if (!str)
		return NULL;

	recode = settings_get_bool("recode");
	if (!recode)
		return g_strdup(str);

	len = strlen(str);

	str_is_utf8 = g_utf8_validate(str, len, NULL);
	translit = settings_get_bool("recode_transliterate");
	
	if (server != NULL && target != NULL)
		tagtarget = server->tag == NULL ? NULL :
			    g_strdup_printf("%s/%s", server->tag, target);
	if (tagtarget != NULL)
		from = iconfig_get_str("conversions", tagtarget, NULL);
	g_free(tagtarget);

	if (target != NULL && from == NULL)
		from = iconfig_get_str("conversions", target, NULL);

	if (from == NULL && server != NULL)
		from = iconfig_get_str("conversions", server->tag, NULL);

	term_is_utf8 = recode_get_charset(&to);

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
#else
	return g_strdup(str);
#endif
}

char *recode_out(const SERVER_REC *server, const char *str, const char *target)
{
#ifdef HAVE_GLIB2
	char *recoded = NULL;
	const char *from = NULL;
	gboolean translit, term_is_utf8, recode;
	int len;

	if (!str)
		return NULL;

	recode = settings_get_bool("recode");
	if (!recode)
		return g_strdup(str);

	len = strlen(str);

	translit = settings_get_bool("recode_transliterate");

	if (target) {
		const char *to = NULL;
		char *translit_to = NULL;
		char *tagtarget = NULL;

		if (server != NULL && target != NULL)
			tagtarget = server->tag == NULL ? NULL :
				    g_strdup_printf("%s/%s", server->tag, target);
		if (tagtarget != NULL)
			to = iconfig_get_str("conversions", tagtarget, NULL);
		g_free(tagtarget);
		if (to == NULL || *to == '\0')
			to = iconfig_get_str("conversions", target, NULL);
		if ((to == NULL || *to == '\0') && server != NULL)
			to = iconfig_get_str("conversions", server->tag, NULL);
		if (to == NULL || *to == '\0')
			/* default outgoing charset if set */
			to = settings_get_str("recode_out_default_charset");

		if (to && *to != '\0') {
			if (translit && !is_translit(to))
				to = translit_to = g_strconcat(to ,"//TRANSLIT", NULL);

			term_is_utf8 = recode_get_charset(&from);
			recoded = g_convert(str, len, to, from, NULL, NULL, NULL);
		}
		g_free(translit_to);
	}
	if (!recoded)
		recoded = g_strdup(str);

	return recoded;
#else
	return g_strdup(str);
#endif
}

void recode_init(void)
{
	settings_add_bool("misc", "recode", TRUE);
	settings_add_str("misc", "recode_fallback", "ISO8859-1");
	settings_add_str("misc", "recode_out_default_charset", "");
	settings_add_bool("misc", "recode_transliterate", FALSE);
}

void recode_deinit(void)
{	
	settings_remove("recode");
	settings_remove("recode_fallback");
	settings_remove("recode_out_default_charset");
	settings_remove("recode_transliterate");
}
