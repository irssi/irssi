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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"

#include "servers.h"
#include "ignore.h"
#include "printtext.h"

static char *ignore_get_key(IGNORE_REC *rec)
{
	char *chans, *ret;

	if (rec->channels == NULL)
		return g_strdup(rec->mask != NULL ? rec->mask : "*" );

	chans = g_strjoinv(",", rec->channels);
	if (rec->mask == NULL) return chans;

	ret = g_strdup_printf("%s %s", rec->mask, chans);
	g_free(chans);
	return ret;
}

static void ignore_print(int index, IGNORE_REC *rec)
{
	GString *options;
	char *key, *levels;

	key = ignore_get_key(rec);
	levels = bits2level(rec->level);

	options = g_string_new(NULL);
	if (rec->exception) g_string_append(options, "-except ");
	if (rec->regexp) {
		g_string_append(options, "-regexp ");
#ifdef HAVE_REGEX_H
		if (!rec->regexp_compiled)
			g_string_append(options, "[INVALID!] ");
#endif
	}
	if (rec->fullword) g_string_append(options, "-full ");
	if (rec->replies) g_string_append(options, "-replies ");
	if (rec->servertag != NULL) 
		g_string_append_printf(options, "-network %s ", rec->servertag);
	if (rec->pattern != NULL)
		g_string_append_printf(options, "-pattern %s ", rec->pattern);

	if (options->len > 1) g_string_truncate(options, options->len-1);

	if (index >= 0) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_IGNORE_LINE, index, key != NULL ? key : "",
			    levels != NULL ? levels : "", options->str);
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    options->len > 0 ? TXT_IGNORED_OPTIONS : TXT_IGNORED,
			    key != NULL ? key : "",
			    levels != NULL ? levels : "", options->str);
	}
	g_string_free(options, TRUE);
        g_free(key);
	g_free(levels);
}

static void cmd_ignore_show(void)
{
	GSList *tmp;
	int index;

	if (ignores == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_IGNORE_NO_IGNORES);
                return;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_IGNORE_HEADER);
	index = 1;
	for (tmp = ignores; tmp != NULL; tmp = tmp->next, index++) {
		IGNORE_REC *rec = tmp->data;

		ignore_print(index, rec);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_IGNORE_FOOTER);
}

/* SYNTAX: IGNORE [-regexp | -full] [-pattern <pattern>] [-except] [-replies]
                  [-network <network>] [-channels <channel>] [-time <secs>] <mask> [<levels>]
           IGNORE [-regexp | -full] [-pattern <pattern>] [-except] [-replies]
	          [-network <network>] [-time <secs>] <channels> [<levels>] */
/* NOTE: -network replaces the old -ircnet flag. */
static void cmd_ignore(const char *data)
{
	GHashTable *optlist;
	IGNORE_REC *rec;
	char *patternarg, *chanarg, *mask, *levels, *timestr, *servertag;
	char **channels;
	void *free_arg;
	int new_ignore, msecs;

	if (*data == '\0') {
		cmd_ignore_show();
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS | PARAM_FLAG_GETREST,
			    "ignore", &optlist, &mask, &levels))
		return;

	patternarg = g_hash_table_lookup(optlist, "pattern");
        chanarg = g_hash_table_lookup(optlist, "channels");
	servertag = g_hash_table_lookup(optlist, "network");
	/* Allow -ircnet for backwards compatibility */
	if (!servertag)
		servertag = g_hash_table_lookup(optlist, "ircnet");
	
	if (*mask == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
        if (*levels == '\0') levels = "ALL";

	msecs = 0;
	timestr = g_hash_table_lookup(optlist, "time");
	if (timestr != NULL) {
		if (!parse_time_interval(timestr, &msecs))
			cmd_param_error(CMDERR_INVALID_TIME);
	}

	if (active_win->active_server != NULL &&
	    server_ischannel(active_win->active_server, mask)) {
		chanarg = mask;
		mask = NULL;
	}
	channels = (chanarg == NULL || *chanarg == '\0') ? NULL :
		g_strsplit(chanarg, ",", -1);

	rec = patternarg != NULL ? NULL: ignore_find(servertag, mask, channels);
	new_ignore = rec == NULL;

	if (rec == NULL) {
		rec = g_new0(IGNORE_REC, 1);

		rec->mask = mask == NULL || *mask == '\0' ||
			strcmp(mask, "*") == 0 ? NULL : g_strdup(mask);
		rec->channels = channels;
	} else {
                g_free_and_null(rec->pattern);
		g_strfreev(channels);
	}

	rec->level = combine_level(rec->level, levels);

	if (new_ignore && rec->level == 0) {
		/* tried to unignore levels from nonexisting ignore */
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_IGNORE_NOT_FOUND, rec->mask);
		g_free(rec->mask);
		g_strfreev(rec->channels);
		g_free(rec);
		cmd_params_free(free_arg);
                return;
	}
	rec->servertag = (servertag == NULL || *servertag == '\0') ?
		NULL : g_strdup(servertag);
	rec->pattern = (patternarg == NULL || *patternarg == '\0') ?
		NULL : g_strdup(patternarg);
	rec->exception = g_hash_table_lookup(optlist, "except") != NULL;
	rec->regexp = g_hash_table_lookup(optlist, "regexp") != NULL;
	rec->fullword = g_hash_table_lookup(optlist, "full") != NULL;
	rec->replies = g_hash_table_lookup(optlist, "replies") != NULL;
	if (msecs != 0)
		rec->unignore_time = time(NULL)+msecs/1000;

	if (new_ignore)
		ignore_add_rec(rec);
	else
		ignore_update_rec(rec);

	cmd_params_free(free_arg);
}

/* SYNTAX: UNIGNORE <id>|<mask> */
static void cmd_unignore(const char *data)
{
	IGNORE_REC *rec;
	GSList *tmp;
        char *mask;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &mask))
		return;

	if (*mask == '\0')
                cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (is_numeric(mask, ' ')) {
		/* with index number */
		tmp = g_slist_nth(ignores, atoi(mask)-1);
		rec = tmp == NULL ? NULL : tmp->data;
	} else {
		/* with mask */
		const char *chans[2] = { "*", NULL };

		if (active_win->active_server != NULL &&
		    server_ischannel(active_win->active_server, mask)) {
			chans[0] = mask;
			mask = NULL;
		}
		rec = ignore_find("*", mask, (char **) chans);
	}

	if (rec != NULL) {
		rec->level = 0;
		ignore_update_rec(rec);
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_IGNORE_NOT_FOUND, mask);
	}
	cmd_params_free(free_arg);
}

static void sig_ignore_created(IGNORE_REC *rec)
{
        ignore_print(-1, rec);
}

static void sig_ignore_destroyed(IGNORE_REC *rec)
{
	char *key;

	key = ignore_get_key(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_UNIGNORED, key);
	g_free(key);
}

void fe_ignore_init(void)
{
	command_bind("ignore", NULL, (SIGNAL_FUNC) cmd_ignore);
	command_bind("unignore", NULL, (SIGNAL_FUNC) cmd_unignore);

	signal_add("ignore destroyed", (SIGNAL_FUNC) sig_ignore_destroyed);
	signal_add("ignore created", (SIGNAL_FUNC) sig_ignore_created);
	signal_add("ignore changed", (SIGNAL_FUNC) sig_ignore_created);

	command_set_options("ignore", "regexp full except replies -network -ircnet -time -pattern -channels");
}

void fe_ignore_deinit(void)
{
	command_unbind("ignore", (SIGNAL_FUNC) cmd_ignore);
	command_unbind("unignore", (SIGNAL_FUNC) cmd_unignore);

	signal_remove("ignore destroyed", (SIGNAL_FUNC) sig_ignore_destroyed);
	signal_remove("ignore created", (SIGNAL_FUNC) sig_ignore_created);
	signal_remove("ignore changed", (SIGNAL_FUNC) sig_ignore_created);
}
