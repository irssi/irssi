#ifndef IRSSI_CORE_IREGEX_H
#define IRSSI_CORE_IREGEX_H

#include <irssi/src/common.h>

#include <glib.h>
typedef	GRegex Regex;
typedef	struct _MatchInfo MatchInfo;

gboolean
i_match_info_matches (const MatchInfo *match_info);

void
i_match_info_free (MatchInfo *match_info);

Regex *
i_regex_new (const gchar *pattern,
             GRegexCompileFlags compile_options,
             GRegexMatchFlags match_options,
             GError **error);

void
i_regex_unref (Regex *regex);

gboolean
i_regex_match (const Regex *regex,
               const gchar *string,
               GRegexMatchFlags match_options,
               MatchInfo **match_info);

gboolean
i_match_info_fetch_pos (const MatchInfo *match_info,
                        gint match_num,
                        gint *start_pos,
                        gint *end_pos);

#endif
