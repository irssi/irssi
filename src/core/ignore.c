/*
 ignore.c : irssi

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
#include "signals.h"
#include "misc.h"
#include "levels.h"
#include "lib-config/iconfig.h"
#include "settings.h"
#include "iregex.h"

#include "masks.h"
#include "servers.h"
#include "channels.h"
#include "nicklist.h"
#include "nickmatch-cache.h"

#include "ignore.h"

GSList *ignores;

static NICKMATCH_REC *nickmatch;
static int time_tag;

/* check if `text' contains ignored nick at the start of the line. */
static int ignore_check_replies_rec(IGNORE_REC *rec, CHANNEL_REC *channel,
				    const char *text)
{
	GSList *nicks, *tmp;

	nicks = nicklist_find_multiple(channel, rec->mask);
	if (nicks == NULL) return FALSE;

	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *nick = tmp->data;

		if (nick_match_msg(channel, text, nick->nick))
			return TRUE;
	}
	g_slist_free(nicks);

	return FALSE;
}

static int ignore_match_pattern(IGNORE_REC *rec, const char *text)
{
	if (rec->pattern == NULL)
		return TRUE;

        if (text == NULL)
		return FALSE;

	if (rec->regexp) {
		return rec->preg != NULL &&
			i_regex_match(rec->preg, text, 0, NULL);
	}

	return rec->fullword ?
		stristr_full(text, rec->pattern) != NULL :
		stristr(text, rec->pattern) != NULL;
}

/* MSGLEVEL_NO_ACT is special in ignores, when provided to ignore_check() it's
 * used as a flag to indicate it should only look at ignore items with NO_ACT.
 * However we also want to allow NO_ACT combined with levels, so mask it out and
 * match levels if set. */
#define ignore_match_level(rec, level) \
        (((level & (MSGLEVEL_NO_ACT|MSGLEVEL_HIDDEN)) != 0) ? \
         ((~(MSGLEVEL_NO_ACT|MSGLEVEL_HIDDEN) & level) & (rec)->level) != 0 : \
         ((rec)->level & (MSGLEVEL_NO_ACT|MSGLEVEL_HIDDEN) ? 0 : \
         (level & (rec)->level) != 0))

#define ignore_match_nickmask(rec, nick, nickmask) \
	((rec)->mask == NULL || \
	(strchr((rec)->mask, '!') != NULL ? \
		match_wildcards((rec)->mask, nickmask) : \
		match_wildcards((rec)->mask, nick)))

#define ignore_match_server(rec, server) \
	((rec)->servertag == NULL || ((server) != NULL && \
		g_ascii_strcasecmp((server)->tag, (rec)->servertag) == 0))

#define ignore_match_channel(rec, channel) \
	((rec)->channels == NULL || ((channel) != NULL && \
		strarray_find((rec)->channels, (channel)) != -1))

static int ignore_check_replies(CHANNEL_REC *chanrec, const char *text, int level)
{
	GSList *tmp;

	if (text == NULL || chanrec == NULL)
		return FALSE;

        /* check reply ignores */
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if (rec->mask != NULL && rec->replies &&
		    ignore_match_level(rec, level) &&
		    ignore_match_channel(rec, chanrec->name) &&
		    ignore_check_replies_rec(rec, chanrec, text))
			return TRUE;
	}

	return FALSE;
}

int ignore_check(SERVER_REC *server, const char *nick, const char *host,
		 const char *channel, const char *text, int level)
{
	CHANNEL_REC *chanrec;
	NICK_REC *nickrec;
        IGNORE_REC *rec;
	GSList *tmp;
        char *nickmask;
        int len, best_mask, best_match, best_patt;

        if (nick == NULL) nick = "";

	chanrec = server == NULL || channel == NULL ? NULL :
		channel_find(server, channel);
	if (chanrec != NULL && nick != NULL &&
	    (nickrec = nicklist_find(chanrec, nick)) != NULL) {
                /* nick found - check only ignores in nickmatch cache */
		if (nickrec->host == NULL)
			nicklist_set_host(chanrec, nickrec, host);

		tmp = nickmatch_find(nickmatch, nickrec);
		nickmask = NULL;
	} else {
		tmp = ignores;
		nickmask = g_strconcat(nick, "!", host, NULL);
	}

        best_mask = best_patt = -1; best_match = FALSE;
	for (; tmp != NULL; tmp = tmp->next) {
		int match = 1;
		rec = tmp->data;

		if (nickmask != NULL)
			match = ignore_match_server(rec, server) &&
				ignore_match_channel(rec, channel) &&
				ignore_match_nickmask(rec, nick, nickmask);
		if (match &&
		    ignore_match_level(rec, level) &&
		    ignore_match_pattern(rec, text)) {
			len = rec->mask == NULL ? 0 : strlen(rec->mask);
			if (len > best_mask) {
				best_mask = len;
				best_match = !rec->exception;
			} else if (len == best_mask) {
				len = rec->pattern == NULL ? 0 : strlen(rec->pattern);
				if (len > best_patt) {
					best_patt = len;
					best_match = !rec->exception;
				} else if (len == best_patt && rec->exception)
					best_match = 0;
			}
		}
	}
        g_free(nickmask);

	if (best_match || (level & MSGLEVEL_PUBLIC) == 0)
		return best_match;

        return ignore_check_replies(chanrec, text, level);
}

IGNORE_REC *ignore_find_full(const char *servertag, const char *mask, const char *pattern,
		char **channels, const int flags)
{
	GSList *tmp;
	char **chan;
	int ignore_servertag;

	if (mask != NULL && (*mask == '\0' || g_strcmp0(mask, "*") == 0))
		mask = NULL;

	ignore_servertag = servertag != NULL && g_strcmp0(servertag, "*") == 0;
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if (!ignore_servertag) {
			if ((servertag == NULL && rec->servertag != NULL) ||
			    (servertag != NULL && rec->servertag == NULL))
				continue;

			if (servertag != NULL && g_ascii_strcasecmp(servertag, rec->servertag) != 0)
				continue;
		}

		if ((flags & IGNORE_FIND_NOACT) && (rec->level & MSGLEVEL_NO_ACT) == 0)
			continue;

		if (!(flags & IGNORE_FIND_NOACT) && (rec->level & MSGLEVEL_NO_ACT) != 0)
			continue;

		if ((flags & IGNORE_FIND_HIDDEN) && (rec->level & MSGLEVEL_HIDDEN) == 0)
			continue;

		if (!(flags & IGNORE_FIND_HIDDEN) && (rec->level & MSGLEVEL_HIDDEN) != 0)
			continue;

		if ((rec->mask == NULL && mask != NULL) ||
		    (rec->mask != NULL && mask == NULL))
			continue;

		if (rec->mask != NULL && g_ascii_strcasecmp(rec->mask, mask) != 0)
			continue;

		/* match the pattern too if requested */
		if (flags & IGNORE_FIND_PATTERN) {
			if ((rec->pattern == NULL && pattern != NULL) ||
			    (rec->pattern != NULL && pattern == NULL))
				continue;

			if (rec->pattern != NULL && g_ascii_strcasecmp(rec->pattern, pattern) != 0)
				continue;
		}

		if ((channels == NULL && rec->channels == NULL))
			return rec; /* no channels - ok */

		if (channels != NULL && g_strcmp0(*channels, "*") == 0)
			return rec; /* ignore channels */

		if (channels == NULL || rec->channels == NULL)
			continue; /* other doesn't have channels */

		if (g_strv_length(channels) != g_strv_length(rec->channels))
			continue; /* different amount of channels */

		/* check that channels match */
		for (chan = channels; *chan != NULL; chan++) {
			if (strarray_find(rec->channels, *chan) == -1)
                                break;
		}

		if (*chan == NULL)
			return rec; /* channels ok */
	}

	return NULL;
}

IGNORE_REC *ignore_find(const char *servertag, const char *mask, char **channels)
{
	return ignore_find_full(servertag, mask, NULL, channels, 0);
}

IGNORE_REC *ignore_find_noact(const char *servertag, const char *mask, char **channels, int noact)
{
	return ignore_find_full(servertag, mask, NULL, channels, IGNORE_FIND_NOACT);
}

IGNORE_REC *ignore_find_hidden(const char *servertag, const char *mask, char **channels, int hidden)
{
	return ignore_find_full(servertag, mask, NULL, channels, IGNORE_FIND_HIDDEN);
}

static void ignore_set_config(IGNORE_REC *rec)
{
	CONFIG_NODE *node;
	char *levelstr;

	if (rec->level == 0)
		return;

	node = iconfig_node_traverse("(ignores", TRUE);
	node = iconfig_node_section(node, NULL, NODE_TYPE_BLOCK);

	if (rec->mask != NULL) iconfig_node_set_str(node, "mask", rec->mask);
	if (rec->level) {
		levelstr = bits2level(rec->level);
		iconfig_node_set_str(node, "level", levelstr);
		g_free(levelstr);
	}
	iconfig_node_set_str(node, "pattern", rec->pattern);
	if (rec->exception) iconfig_node_set_bool(node, "exception", TRUE);
	if (rec->regexp) iconfig_node_set_bool(node, "regexp", TRUE);
	if (rec->fullword) iconfig_node_set_bool(node, "fullword", TRUE);
	if (rec->replies) iconfig_node_set_bool(node, "replies", TRUE);
	if (rec->unignore_time != 0)
		iconfig_node_set_int(node, "unignore_time", rec->unignore_time);
	iconfig_node_set_str(node, "servertag", rec->servertag);

	if (rec->channels != NULL && *rec->channels != NULL) {
		node = iconfig_node_section(node, "channels", NODE_TYPE_LIST);
		iconfig_node_add_list(node, rec->channels);
	}
}

static int ignore_index(IGNORE_REC *find)
{
	GSList *tmp;
	int index;

	index = 0;
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if (rec == find)
			return index;
		index++;
	}

	return -1;
}

static void ignore_remove_config(IGNORE_REC *rec)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("ignores", FALSE);
	if (node != NULL) iconfig_node_list_remove(node, ignore_index(rec));
}

static void ignore_init_rec(IGNORE_REC *rec)
{
	if (rec->preg != NULL)
		i_regex_unref(rec->preg);

	if (rec->regexp && rec->pattern != NULL) {
		GError *re_error = NULL;

		rec->preg = i_regex_new(rec->pattern, G_REGEX_OPTIMIZE | G_REGEX_CASELESS, 0, &re_error);

		if (rec->preg == NULL) {
			g_warning("Failed to compile regexp '%s': %s", rec->pattern, re_error->message);
			g_error_free(re_error);
		}
	}
}

void ignore_add_rec(IGNORE_REC *rec)
{
	ignore_init_rec(rec);

	ignores = g_slist_append(ignores, rec);
	ignore_set_config(rec);

	signal_emit("ignore created", 1, rec);
	nickmatch_rebuild(nickmatch);
}

static void ignore_destroy(IGNORE_REC *rec, int send_signal)
{
	ignores = g_slist_remove(ignores, rec);
	if (send_signal)
		signal_emit("ignore destroyed", 1, rec);

	if (rec->preg != NULL) i_regex_unref(rec->preg);
	if (rec->channels != NULL) g_strfreev(rec->channels);
	g_free_not_null(rec->mask);
	g_free_not_null(rec->servertag);
	g_free_not_null(rec->pattern);
	g_free(rec);
}

void ignore_update_rec(IGNORE_REC *rec)
{
	if (rec->level == 0) {
		/* unignored everything */
		ignore_remove_config(rec);
		ignore_destroy(rec, TRUE);
	} else {
		/* unignore just some levels.. */
		ignore_remove_config(rec);
		ignores = g_slist_remove(ignores, rec);

		ignores = g_slist_append(ignores, rec);
		ignore_set_config(rec);

                ignore_init_rec(rec);
		signal_emit("ignore changed", 1, rec);
	}
        nickmatch_rebuild(nickmatch);
}

static int unignore_timeout(void)
{
	GSList *tmp, *next;
        time_t now;

        now = time(NULL);
	for (tmp = ignores; tmp != NULL; tmp = next) {
		IGNORE_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->unignore_time > 0 && now >= rec->unignore_time) {
			rec->level = 0;
			ignore_update_rec(rec);
		}
	}

	return TRUE;
}

static void read_ignores(void)
{
	IGNORE_REC *rec;
	CONFIG_NODE *node;
	GSList *tmp;

	while (ignores != NULL)
                ignore_destroy(ignores->data, FALSE);

	node = iconfig_node_traverse("ignores", FALSE);
	if (node == NULL) {
		nickmatch_rebuild(nickmatch);
		return;
	}

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		rec = g_new0(IGNORE_REC, 1);
		ignores = g_slist_append(ignores, rec);

		rec->mask = g_strdup(config_node_get_str(node, "mask", NULL));
		rec->pattern = g_strdup(config_node_get_str(node, "pattern", NULL));
		rec->level = level2bits(config_node_get_str(node, "level", ""), NULL);
                rec->exception = config_node_get_bool(node, "exception", FALSE);
		rec->regexp = config_node_get_bool(node, "regexp", FALSE);
		rec->fullword = config_node_get_bool(node, "fullword", FALSE);
		rec->replies = config_node_get_bool(node, "replies", FALSE);
		rec->unignore_time = config_node_get_int(node, "unignore_time", 0);
		rec->servertag = g_strdup(config_node_get_str(node, "servertag", 0));

		node = iconfig_node_section(node, "channels", -1);
		if (node != NULL) rec->channels = config_node_get_list(node);

		ignore_init_rec(rec);
	}

	nickmatch_rebuild(nickmatch);
}

static void ignore_nick_cache(GHashTable *list, CHANNEL_REC *channel,
			      NICK_REC *nick)
{
	GSList *tmp, *matches;
        char *nickmask;

	if (nick->host == NULL)
		return; /* don't check until host is known */

        matches = NULL;
	nickmask = g_strconcat(nick->nick, "!", nick->host, NULL);
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if (ignore_match_nickmask(rec, nick->nick, nickmask) &&
		    ignore_match_server(rec, channel->server) &&
		    ignore_match_channel(rec, channel->name))
			matches = g_slist_append(matches, rec);
	}
	g_free_not_null(nickmask);

	if (matches == NULL)
		g_hash_table_remove(list, nick);
        else
                g_hash_table_insert(list, nick, matches);
}

void ignore_init(void)
{
	ignores = NULL;
	nickmatch = nickmatch_init(ignore_nick_cache);
	time_tag = g_timeout_add(1000, (GSourceFunc) unignore_timeout, NULL);

        read_ignores();
        signal_add("setup reread", (SIGNAL_FUNC) read_ignores);
}

void ignore_deinit(void)
{
	g_source_remove(time_tag);
	while (ignores != NULL)
                ignore_destroy(ignores->data, TRUE);
        nickmatch_deinit(nickmatch);

	signal_remove("setup reread", (SIGNAL_FUNC) read_ignores);
}
