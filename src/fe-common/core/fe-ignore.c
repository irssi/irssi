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
#include <time.h>
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/core/servers.h>
#include <irssi/src/core/ignore.h>
#include <irssi/src/fe-common/core/printtext.h>

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
	struct tm ts;
	char buf[20];

	key = ignore_get_key(rec);
	levels = bits2level(rec->level);

	options = g_string_new(NULL);
	if (rec->exception) g_string_append(options, "-except ");
	if (rec->regexp) {
		g_string_append(options, "-regexp ");
		if (rec->pattern == NULL)
			g_string_append(options, "[INVALID! -pattern missing] ");
		else if (rec->preg == NULL)
			g_string_append(options, "[INVALID!] ");
	}
	if (rec->fullword) g_string_append(options, "-full ");
	if (rec->replies) g_string_append(options, "-replies ");
	if (rec->servertag != NULL)
		g_string_append_printf(options, "-network %s ", rec->servertag);
	if (rec->pattern != NULL)
		g_string_append_printf(options, "-pattern %s ", rec->pattern);
	if (rec->comment != NULL)
		g_string_append_printf(options, "-comment %s ", rec->comment);
	if (rec->unignore_time != 0) {
		ts = *localtime(&rec->unignore_time);
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &ts);
		g_string_append_printf(options, "ignore ends: %s ", buf);
	}

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

/* SYNTAX: IGNORE [-regexp | -full] [-oldpattern <pattern>] [-pattern <pattern>] [-except]
                  [-replies] [-network <network>] [-channels <channel>] [-comment <comment>]
                  [-time <time>] <mask> [<levels>]
           IGNORE [-regexp | -full] [-oldpattern <pattern>] [-pattern <pattern>] [-except]
                  [-replies] [-network <network>] [-time <time>] [-comment <comment>] <channels>
                  [<levels>]
           IGNORE [-regexp | -noregexp | -full | -nofull] [-pattern <pattern>] [-except | -noexcept]
                  [-replies | -noreplies] [-network <network>] [-channels <channel>]
                  [-comment <comment] [-time <time>] [-mask <mask>] <id> [<levels>] */
/* NOTE: -network replaces the old -ircnet flag. */
static void cmd_ignore(const char *data)
{
	GHashTable *optlist;
	IGNORE_REC *rec;
	char *oldpattern, *patternarg, *chanarg, *mask, *levels, *timestr, *servertag, *comment;
	char **channels;
	void *free_arg;
	int new_ignore, modify_ignore, msecs, level, nolev, flags, exception;

	if (*data == '\0') {
		cmd_ignore_show();
		return;
	}

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS | 
			    PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS,
			    "ignore", &optlist, &mask, &levels))
		return;

	oldpattern = g_hash_table_lookup(optlist, "oldpattern");
	patternarg = g_hash_table_lookup(optlist, "pattern");
	if (oldpattern == NULL)
		oldpattern = patternarg;
	chanarg = g_hash_table_lookup(optlist, "channels");
	servertag = g_hash_table_lookup(optlist, "network");
	comment = g_hash_table_lookup(optlist, "comment");
	exception = g_hash_table_lookup(optlist, "except") != NULL;
	/* Allow -ircnet for backwards compatibility */
	if (!servertag)
		servertag = g_hash_table_lookup(optlist, "ircnet");

	if (*mask == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	level = level2bits(levels, NULL);
	nolev = (~combine_level(MSGLEVEL_ALL, levels)) & MSGLEVEL_ALL;

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

	if (is_numeric(mask, '\0')) {
		/* with index number */
		GSList *tmp;

		if (oldpattern != patternarg) {
			g_strfreev(channels);
			cmd_param_error(CMDERR_OPTION_UNKNOWN);
		}

		if ((g_hash_table_lookup(optlist, "except") != NULL &&
		     g_hash_table_lookup(optlist, "noexcept") != NULL) ||
		    (g_hash_table_lookup(optlist, "regexp") != NULL &&
		     g_hash_table_lookup(optlist, "noregexp") != NULL) ||
		    (g_hash_table_lookup(optlist, "full") != NULL &&
		     g_hash_table_lookup(optlist, "nofull") != NULL) ||
		    (g_hash_table_lookup(optlist, "replies") != NULL &&
		     g_hash_table_lookup(optlist, "noreplies") != NULL)) {
			g_strfreev(channels);
			cmd_param_error(CMDERR_OPTION_AMBIGUOUS);
		}

		tmp = g_slist_nth(ignores, atoi(mask) - 1);
		if (tmp == NULL) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_IGNORE_NOT_FOUND, mask);
			g_strfreev(channels);
			cmd_params_free(free_arg);
			return;
		} else {
			rec = tmp->data;
			mask = g_hash_table_lookup(optlist, "mask");
			modify_ignore = TRUE;
		}
	} else {
		if (g_hash_table_lookup(optlist, "mask") != NULL) {
			g_strfreev(channels);
			cmd_param_error(CMDERR_OPTION_UNKNOWN);
		}

		flags = (oldpattern == NULL || g_strcmp0(oldpattern, "*") != 0) ?
		            IGNORE_FIND_PATTERN :
		            0;
		if (level & MSGLEVEL_NO_ACT)
			flags |= IGNORE_FIND_NO_ACT;
		if (level & MSGLEVEL_HIDDEN)
			flags |= IGNORE_FIND_HIDDEN;
		if (level & MSGLEVEL_NOHILIGHT)
			flags |= IGNORE_FIND_NOHILIGHT;
		if (exception)
			flags |= IGNORE_FIND_EXCEPT;

		rec = ignore_find_full(servertag, mask, oldpattern, channels, flags);
		modify_ignore = FALSE;
	}
	new_ignore = rec == NULL;

	if (rec == NULL) {
		rec = g_new0(IGNORE_REC, 1);
	}

	if (new_ignore || (modify_ignore && mask != NULL)) {
		rec->mask = mask == NULL || *mask == '\0' ||
			g_strcmp0(mask, "*") == 0 ? NULL : g_strdup(mask);
	}

	if (new_ignore || (modify_ignore && chanarg != NULL)) {
		rec->channels =
		    (channels == NULL || g_strcmp0(*channels, "*") == 0) ? NULL : channels;
	} else {
		g_strfreev(channels);
	}

	rec->level = combine_level(rec->level, levels);

	if (new_ignore && rec->level == 0 && nolev != 0) {
		/* tried to unignore levels from nonexisting ignore */
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_IGNORE_NOT_FOUND,
		            mask == NULL ? (chanarg == NULL ? "*" : chanarg) : mask);
		g_free(rec->mask);
		g_strfreev(rec->channels);
		g_free(rec);
		cmd_params_free(free_arg);
		return;
	}

	if (nolev == 0 &&
	    (rec->level & ~(MSGLEVEL_NO_ACT | MSGLEVEL_HIDDEN | MSGLEVEL_NOHILIGHT)) == 0) {
		/* If only NO_ACT / HIDDEN / NOHILIGHT was specified, add all levels; it makes no
		 * sense on its own. */
		rec->level |= MSGLEVEL_ALL;
	}

	if (new_ignore || (modify_ignore && servertag != NULL)) {
		g_free(rec->servertag);

		rec->servertag =
		    servertag == NULL || *servertag == '\0' || g_strcmp0(servertag, "*") == 0 ?
		        NULL :
		        g_strdup(servertag);
	}

	if (comment != NULL) {
		g_free(rec->comment);
		rec->comment = *comment == '\0' ? NULL : g_strdup(comment);
	}

	if (patternarg != NULL && g_strcmp0(patternarg, "*") != 0) {
		g_free(rec->pattern);
		rec->pattern = *patternarg == '\0' ? NULL : g_strdup(patternarg);
	}

	if (modify_ignore) {
		if (g_hash_table_lookup(optlist, "except") != NULL)
			rec->exception = TRUE;
		else if (g_hash_table_lookup(optlist, "noexcept") != NULL)
			rec->exception = FALSE;
	} else {
		rec->exception = exception;
	}

	if (modify_ignore) {
		if (g_hash_table_lookup(optlist, "regexp") != NULL)
			rec->regexp = TRUE;
		else if (g_hash_table_lookup(optlist, "noregexp") != NULL)
			rec->regexp = FALSE;

		if (g_hash_table_lookup(optlist, "full") != NULL)
			rec->fullword = TRUE;
		else if (g_hash_table_lookup(optlist, "nofull") != NULL)
			rec->fullword = FALSE;

		if (g_hash_table_lookup(optlist, "replies") != NULL)
			rec->replies = TRUE;
		else if (g_hash_table_lookup(optlist, "noreplies") != NULL)
			rec->replies = FALSE;
	} else if (new_ignore || patternarg != NULL) {
		rec->regexp = g_hash_table_lookup(optlist, "regexp") != NULL;
		rec->fullword = g_hash_table_lookup(optlist, "full") != NULL;
		rec->replies = g_hash_table_lookup(optlist, "replies") != NULL;
	}

	if (msecs != 0)
		rec->unignore_time = time(NULL)+msecs/1000;
	else if (modify_ignore && timestr != NULL)
		rec->unignore_time = 0;

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
        char *mask, *mask_orig;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &mask))
		return;

	if (*mask == '\0')
                cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	/* Save the mask string here since it might be modified in the code
	 * below and we need it to print meaningful error messages. */
	mask_orig = mask;

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
		rec = ignore_find_full("*", mask, NULL, (char **) chans, IGNORE_FIND_ANY);
	}

	if (rec != NULL) {
		rec->level = 0;
		ignore_update_rec(rec);
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_IGNORE_NOT_FOUND, mask_orig);
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

	command_set_options(
	    "ignore",
	    "regexp noregexp full nofull except noexcept replies noreplies -network ~-ircnet -time "
	    "-oldpattern -pattern -mask -channels -comment");
}

void fe_ignore_deinit(void)
{
	command_unbind("ignore", (SIGNAL_FUNC) cmd_ignore);
	command_unbind("unignore", (SIGNAL_FUNC) cmd_unignore);

	signal_remove("ignore destroyed", (SIGNAL_FUNC) sig_ignore_destroyed);
	signal_remove("ignore created", (SIGNAL_FUNC) sig_ignore_created);
	signal_remove("ignore changed", (SIGNAL_FUNC) sig_ignore_created);
}
