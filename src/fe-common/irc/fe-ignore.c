/*
 fe-ignore.c : irssi

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
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"

#include "irc.h"
#include "irc-servers.h"
#include "ignore.h"

static void fe_unignore(IGNORE_REC *rec);

static char *ignore_get_key(IGNORE_REC *rec)
{
	char *chans, *ret;

	if (rec->channels == NULL)
		return rec->mask != NULL ? g_strdup(rec->mask) : NULL;

	chans = g_strjoinv(",", rec->channels);
	if (rec->mask == NULL) return chans;

	ret = g_strdup_printf("%s %s", rec->mask, chans);
	g_free(chans);
	return ret;
}

static char *ignore_get_levels(int level, int xlevel)
{
	GString *str;
	char *levelstr, *p, *ret;

	str = g_string_new(NULL);
	if (level != 0) {
		levelstr = bits2level(level);
		g_string_append(str, levelstr);
                g_free(levelstr);
	}

	if (xlevel != 0) {
		if (str->len > 0) g_string_append_c(str, ' ');

		levelstr = bits2level(xlevel);
		for (p = levelstr; *p != '\0'; p++) {
			if (!isspace(*p) && (p == levelstr || isspace(p[-1])))
				g_string_append_c(str, '^');
			g_string_append_c(str, *p);
		}
		g_free(levelstr);
	}

	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

/* msgs ^notices : level=msgs, xlevel=notices */
static void ignore_split_levels(const char *levels, int *level, int *xlevel)
{
	GString *slevel, *sxlevel;
	char **levellist, **tmp;

	if (*levels == '\0') return;

        slevel = g_string_new(NULL);
        sxlevel = g_string_new(NULL);

	levellist = g_strsplit(levels, " ", -1);
	for (tmp = levellist; *tmp != NULL; tmp++) {
		if (**tmp == '^')
			g_string_sprintfa(sxlevel, "%s ", (*tmp)+1);
		else if (**tmp == '-' && (*tmp)[1] == '^')
			g_string_sprintfa(sxlevel, "-%s ", (*tmp)+2);
		else
			g_string_sprintfa(slevel, "%s ", *tmp);
	}
	g_strfreev(levellist);

	*level = combine_level(*level, slevel->str);
	*xlevel = combine_level(*xlevel, sxlevel->str);

	g_string_free(slevel, TRUE);
	g_string_free(sxlevel, TRUE);
}

static void ignore_print(int index, IGNORE_REC *rec)
{
	GString *options;
	char *key, *levels;

	key = ignore_get_key(rec);
	levels = ignore_get_levels(rec->level, rec->except_level);

	options = g_string_new(NULL);
	if (rec->regexp) g_string_sprintfa(options, "-regexp ");
	if (rec->fullword) g_string_sprintfa(options, "-word ");
	if (rec->replies) g_string_sprintfa(options, "-replies ");
	if (options->len > 1) g_string_truncate(options, options->len-1);

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    IRCTXT_IGNORE_LINE, index,
		    key != NULL ? key : "",
		    levels != NULL ? levels : "", options->str);
	g_string_free(options, TRUE);
        g_free(key);
	g_free(levels);
}

static int unignore_timeout(IGNORE_REC *rec)
{
	fe_unignore(rec);
	return FALSE;
}

static void cmd_ignore_show(void)
{
	GSList *tmp;
	int index;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_IGNORE_HEADER);
	index = 1;
	for (tmp = ignores; tmp != NULL; tmp = tmp->next, index++) {
		IGNORE_REC *rec = tmp->data;

		ignore_print(index, rec);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_IGNORE_FOOTER);
}

/* SYNTAX: IGNORE [-regexp | -word] [-pattern <pattern>] [-except] [-replies]
                  [-channels <channel>] [-time <secs>] <mask> <levels>
           IGNORE [-regexp | -word] [-pattern <pattern>] [-except] [-replies]
	          [-time <secs>] <channels> <levels> */
static void cmd_ignore(const char *data)
{
        GHashTable *optlist;
	IGNORE_REC *rec;
	char *patternarg, *chanarg, *mask, *levels, *key, *timestr;
	char **channels;
	void *free_arg;
	int new_ignore;

	if (*data == '\0') {
		cmd_ignore_show();
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS | PARAM_FLAG_GETREST,
			    "ignore", &optlist, &mask, &levels))
		return;

	patternarg = g_hash_table_lookup(optlist, "pattern");
        chanarg = g_hash_table_lookup(optlist, "channels");

	if (*levels == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (ischannel(*mask)) {
		chanarg = mask;
		mask = NULL;
	}
	channels = (chanarg == NULL || *chanarg == '\0') ? NULL :
		g_strsplit(replace_chars(chanarg, ',', ' '), " ", -1);

	rec = ignore_find(NULL, mask, channels);
	new_ignore = rec == NULL;

	if (rec == NULL) {
		rec = g_new0(IGNORE_REC, 1);

		rec->mask = (mask != NULL && *mask != '\0') ?
			g_strdup(mask) : NULL;
		rec->channels = channels;
	} else {
                g_free_and_null(rec->pattern);
		g_strfreev(channels);
	}

	if (g_hash_table_lookup(optlist, "except") != NULL) {
                rec->except_level = combine_level(rec->except_level, levels);
	} else {
		ignore_split_levels(levels, &rec->level, &rec->except_level);
	}

	rec->pattern = (patternarg == NULL || *patternarg == '\0') ?
		NULL : g_strdup(patternarg);
	rec->regexp = g_hash_table_lookup(optlist, "regexp") != NULL;
	rec->fullword = g_hash_table_lookup(optlist, "word") != NULL;
	rec->replies = g_hash_table_lookup(optlist, "replies") != NULL;
	timestr = g_hash_table_lookup(optlist, "time");
	rec->time = timestr == NULL ? 0 : atoi(timestr);

	if (rec->level == 0 && rec->except_level == 0) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_UNIGNORED,
			    rec->mask == NULL ? "" : rec->mask);
	} else {
		key = ignore_get_key(rec);
		levels = ignore_get_levels(rec->level, rec->except_level);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_IGNORED, key, levels);
		g_free(key);
		g_free(levels);
	}

	if (rec->time > 0)
		rec->time_tag = g_timeout_add(rec->time*1000, (GSourceFunc) unignore_timeout, rec);

	if (new_ignore)
		ignore_add_rec(rec);
	else
		ignore_update_rec(rec);

	cmd_params_free(free_arg);
}

static void fe_unignore(IGNORE_REC *rec)
{
	char *key;

	key = ignore_get_key(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_UNIGNORED, key);
	g_free(key);

	rec->level = 0;
	rec->except_level = 0;
	ignore_update_rec(rec);
}

/* SYNTAX: UNIGNORE <id>|<mask> */
static void cmd_unignore(const char *data)
{
	IGNORE_REC *rec;
	GSList *tmp;

	if (is_numeric(data, ' ')) {
		/* with index number */
		tmp = g_slist_nth(ignores, atoi(data)-1);
		rec = tmp == NULL ? NULL : tmp->data;
	} else {
		/* with mask */
		const char *chans[2] = { "*", NULL };

		if (ischannel(*data)) chans[0] = data;
		rec = ignore_find("*", ischannel(*data) ? NULL : data, (char **) chans);
	}

	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_IGNORE_NOT_FOUND, data);
	else
                fe_unignore(rec);
}

void fe_ignore_init(void)
{
	command_bind("ignore", NULL, (SIGNAL_FUNC) cmd_ignore);
	command_bind("unignore", NULL, (SIGNAL_FUNC) cmd_unignore);

	command_set_options("ignore", "regexp word except replies -time -pattern -channels");
}

void fe_ignore_deinit(void)
{
	command_unbind("ignore", (SIGNAL_FUNC) cmd_ignore);
	command_unbind("unignore", (SIGNAL_FUNC) cmd_unignore);
}
