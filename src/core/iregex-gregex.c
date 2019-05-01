#include <string.h>

#include <irssi/src/core/iregex.h>

struct _MatchInfo {
	const char *valid_string;
	GMatchInfo *g_match_info;
};

static const gchar *
make_valid_utf8(const gchar *text, gboolean *free_ret)
{
	GString *str;
	const gchar *ptr;
	if (g_utf8_validate(text, -1, NULL)) {
		if (free_ret)
			*free_ret = FALSE;
		return text;
	}

	str = g_string_sized_new(strlen(text) + 12);

	ptr = text;
	while (*ptr) {
		gunichar c = g_utf8_get_char_validated(ptr, -1);
		/* the unicode is invalid */
		if (c == (gunichar)-1 || c == (gunichar)-2) {
			/* encode the byte into PUA-A */
			g_string_append_unichar(str, (gunichar) (0xfff00 | (*ptr & 0xff)));
			ptr++;
		} else {
			g_string_append_unichar(str, c);
			ptr = g_utf8_next_char(ptr);
		}
	}

	if (free_ret)
		*free_ret = TRUE;
	return g_string_free(str, FALSE);
}

Regex *
i_regex_new (const gchar *pattern,
             GRegexCompileFlags compile_options,
             GRegexMatchFlags match_options,
             GError **error)
{
	const gchar *valid_pattern;
	gboolean free_valid_pattern;
	Regex *ret = NULL;

	valid_pattern = make_valid_utf8(pattern, &free_valid_pattern);
	ret = g_regex_new(valid_pattern, compile_options, match_options, error);

	if (free_valid_pattern)
		g_free_not_null((gchar *)valid_pattern);

	return ret;
}

void
i_regex_unref (Regex *regex)
{
	g_regex_unref(regex);
}

gboolean
i_regex_match (const Regex *regex,
               const gchar *string,
               GRegexMatchFlags match_options,
               MatchInfo **match_info)
{
	gboolean ret;
	gboolean free_valid_string;
	const gchar *valid_string = make_valid_utf8(string, &free_valid_string);

	if (match_info != NULL)
		*match_info = g_new0(MatchInfo, 1);

	ret = g_regex_match(regex, valid_string, match_options,
			    match_info != NULL ? &(*match_info)->g_match_info : NULL);

	if (free_valid_string) {
		if (match_info != NULL)
			(*match_info)->valid_string = valid_string;
		else
			g_free_not_null((gchar *)valid_string);
	}

	return ret;
}

static gsize
strlen_pua_oddly(const char *str)
{
	const gchar *ptr;
	gsize ret = 0;
	ptr = str;

	while (*ptr) {
		const gchar *old;
		gunichar c = g_utf8_get_char(ptr);
		old = ptr;
		ptr = g_utf8_next_char(ptr);

		/* it is our PUA encoded byte */
		if ((c & 0xfff00) == 0xfff00)
			ret++;
		else
			ret += ptr - old;
	}

	return ret;
}

/* new_string should be passed in here from the i_regex_match call. 
   The start_pos and end_pos will then be calculated as if they were on
   the original string */
gboolean
i_match_info_fetch_pos (const MatchInfo *match_info,
                        gint match_num,
                        gint *start_pos,
                        gint *end_pos)
{
	gint tmp_start, tmp_end, new_start_pos;
	gboolean ret;

	if (!match_info->valid_string || (!start_pos && !end_pos))
		return g_match_info_fetch_pos(match_info->g_match_info,
					      match_num, start_pos, end_pos);

	ret = g_match_info_fetch_pos(match_info->g_match_info,
				     match_num, &tmp_start, &tmp_end);
	if (start_pos || end_pos) {
		const gchar *str = match_info->valid_string;
		gchar *to_start = g_strndup(str, tmp_start);
		new_start_pos = strlen_pua_oddly(to_start);
		g_free_not_null(to_start);

		if (start_pos)
			*start_pos = new_start_pos;

		if (end_pos) {
			gchar *to_end = g_strndup(str + tmp_start, tmp_end - tmp_start);
			*end_pos = new_start_pos + strlen_pua_oddly(to_end);
			g_free_not_null(to_end);
		}
	}
	return ret;
}

gboolean
i_match_info_matches (const MatchInfo *match_info)
{
	g_return_val_if_fail(match_info != NULL, FALSE);

	return g_match_info_matches(match_info->g_match_info);
}

void
i_match_info_free (MatchInfo *match_info)
{
	g_match_info_free(match_info->g_match_info);
	g_free(match_info);
}
