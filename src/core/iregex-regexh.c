#include "iregex.h"

Regex *
i_regex_new (const gchar *pattern,
             GRegexCompileFlags compile_options,
             GRegexMatchFlags match_options,
             GError **error)
{
	Regex *regex;
	char *errbuf;
	int cflags;
	int errcode, errbuf_len;

	regex = g_new0(Regex, 1);
	cflags = REG_EXTENDED;
	if (compile_options & G_REGEX_CASELESS)
		cflags |= REG_ICASE;
	if (compile_options & G_REGEX_MULTILINE)
		cflags |= REG_NEWLINE;
	if (match_options & G_REGEX_MATCH_NOTBOL)
		cflags |= REG_NOTBOL;
	if (match_options & G_REGEX_MATCH_NOTEOL)
		cflags |= REG_NOTEOL;

	errcode = regcomp(regex, pattern, cflags);
	if (errcode != 0) {
		errbuf_len = regerror(errcode, regex, 0, 0);
		errbuf = g_malloc(errbuf_len);
		regerror(errcode, regex, errbuf, errbuf_len);
		g_set_error(error, G_REGEX_ERROR, errcode, "%s", errbuf);
		g_free(errbuf);
		g_free(regex);
		return NULL;
	} else {
		return regex;
	}
}

void
i_regex_unref (Regex *regex)
{
	regfree(regex);
	g_free(regex);
}

gboolean
i_regex_match (const Regex *regex,
               const gchar *string,
               GRegexMatchFlags match_options,
               MatchInfo **match_info)
{
	int groups;
	int eflags;

	g_return_val_if_fail(regex != NULL, FALSE);

	if (match_info != NULL) {
		groups = 1 + regex->re_nsub;
		*match_info = g_new0(MatchInfo, groups);
	} else {
		groups = 0;
	}

	eflags = 0;
	if (match_options & G_REGEX_MATCH_NOTBOL)
		eflags |= REG_NOTBOL;
	if (match_options & G_REGEX_MATCH_NOTEOL)
		eflags |= REG_NOTEOL;

	return regexec(regex, string, groups, groups ? *match_info : NULL, eflags) == 0;
}

gboolean
i_match_info_fetch_pos (const MatchInfo *match_info,
                        gint match_num,
                        gint *start_pos,
                        gint *end_pos)
{
	if (start_pos != NULL)
		*start_pos = match_info[match_num].rm_so;
	if (end_pos != NULL)
		*end_pos = match_info[match_num].rm_eo;

	return TRUE;
}

gboolean
i_match_info_matches (const MatchInfo *match_info)
{
	g_return_val_if_fail(match_info != NULL, FALSE);

	return match_info[0].rm_so != -1;
}

void
i_match_info_free (MatchInfo *match_info)
{
	g_free(match_info);
}
