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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "levels.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "masks.h"
#include "servers.h"
#include "channels.h"
#include "nicklist.h"

#include "ignore.h"

GSList *ignores;

/* check if `text' contains ignored nick at the start of the line. */
static int ignore_check_replies(IGNORE_REC *rec, CHANNEL_REC *channel,
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

int ignore_check(SERVER_REC *server, const char *nick, const char *host,
		 const char *channel, const char *text, int level)
{
	CHANNEL_REC *chanrec;
	GSList *tmp;
	int ok, mask_len, patt_len;
	int best_mask, best_patt, best_ignore;

	g_return_val_if_fail(server != NULL, 0);

	chanrec = (channel != NULL && server != NULL &&
		   server->ischannel(channel)) ?
		channel_find(server, channel) : NULL;

	best_mask = 0; best_patt = 0; best_ignore = FALSE;
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if ((level & (rec->level|rec->except_level)) == 0)
			continue;

		/* server */
		if (rec->servertag != NULL && g_strcasecmp(server->tag, rec->servertag) != 0)
			continue;

		/* channel list */
		if (rec->channels != NULL) {
			if (chanrec == NULL ||
			    strarray_find(rec->channels, channel) == -1)
				continue;
		}

		/* nick mask */
		mask_len = 0;
		if (rec->mask != NULL) {
			if (nick == NULL)
				continue;

			mask_len = strlen(rec->mask);
			if (mask_len <= best_mask) continue;

			ok = ((host == NULL || *host == '\0')) ?
				match_wildcards(rec->mask, nick) :
				mask_match_address(server, rec->mask, nick, host);
			if (!ok) {
                                /* nick didn't match, but maybe this is a reply to nick? */
				if (!rec->replies || chanrec == NULL || text == NULL ||
				    !ignore_check_replies(rec, chanrec, text))
					continue;
			}
		}

		/* pattern */
		patt_len = 0;
		if (rec->pattern != NULL) {
			if (text == NULL)
				continue;

			if (!mask_len && !best_mask) {
				patt_len = strlen(rec->pattern);
				if (patt_len <= best_patt) continue;
			}

#ifdef HAVE_REGEX_H
			if (rec->regexp) {
				ok = !rec->regexp_compiled ? FALSE :
					regexec(&rec->preg, text, 0, NULL, 0) == 0;
			} else
#endif
			{
				ok = rec->fullword ?
					stristr_full(text, rec->pattern) != NULL :
					stristr(text, rec->pattern) != NULL;
			}
			if (!ok) continue;
		}

		if (mask_len || best_mask)
			best_mask = mask_len;
		else if (patt_len)
			best_patt = patt_len;

		best_ignore = (rec->level & level) != 0;
	}

	return best_ignore;
}

IGNORE_REC *ignore_find(const char *servertag, const char *mask, char **channels)
{
	GSList *tmp;
	char **chan;
	int ignore_servertag;

	if (mask != NULL && *mask == '\0') mask = NULL;

	ignore_servertag = servertag != NULL && strcmp(servertag, "*") == 0;
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		IGNORE_REC *rec = tmp->data;

		if (!ignore_servertag) {
			if ((servertag == NULL && rec->servertag != NULL) ||
			    (servertag != NULL && rec->servertag == NULL))
				continue;

			if (servertag != NULL && g_strcasecmp(servertag, rec->servertag) != 0)
				continue;
		}

		if ((rec->mask == NULL && mask != NULL) ||
		    (rec->mask != NULL && mask == NULL)) continue;

		if (rec->mask != NULL && g_strcasecmp(rec->mask, mask) != 0)
			continue;

		if ((channels == NULL && rec->channels == NULL))
			return rec; /* no channels - ok */

		if (channels != NULL && strcmp(*channels, "*") == 0)
			return rec; /* ignore channels */

		if (channels == NULL || rec->channels == NULL)
			continue; /* other doesn't have channels */

		if (strarray_length(channels) != strarray_length(rec->channels))
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

static void ignore_set_config(IGNORE_REC *rec)
{
	CONFIG_NODE *node;
	char *levelstr;

	if (rec->level == 0 && rec->except_level == 0)
		return;

	if (rec->time > 0)
		return;

	node = iconfig_node_traverse("(ignores", TRUE);
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

	if (rec->mask != NULL) iconfig_node_set_str(node, "mask", rec->mask);
	if (rec->level) {
		levelstr = bits2level(rec->level);
		iconfig_node_set_str(node, "level", levelstr);
		g_free(levelstr);
	}
	if (rec->except_level) {
		levelstr = bits2level(rec->except_level);
		iconfig_node_set_str(node, "except_level", levelstr);
		g_free(levelstr);
	}
	iconfig_node_set_str(node, "pattern", rec->pattern);
	if (rec->regexp) iconfig_node_set_bool(node, "regexp", TRUE);
	if (rec->fullword) iconfig_node_set_bool(node, "fullword", TRUE);
	if (rec->replies) iconfig_node_set_bool(node, "replies", TRUE);

	if (rec->channels != NULL && *rec->channels != NULL) {
		node = config_node_section(node, "channels", NODE_TYPE_LIST);
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

		if (rec->servertag != NULL)
			continue;

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

void ignore_add_rec(IGNORE_REC *rec)
{
#ifdef HAVE_REGEX_H
	rec->regexp_compiled = !rec->regexp || rec->pattern == NULL ? FALSE :
		regcomp(&rec->preg, rec->pattern,
			REG_EXTENDED|REG_ICASE|REG_NOSUB) == 0;
#endif
	ignores = g_slist_append(ignores, rec);
	ignore_set_config(rec);

	signal_emit("ignore created", 1, rec);
}

static void ignore_destroy(IGNORE_REC *rec)
{
	ignores = g_slist_remove(ignores, rec);
	signal_emit("ignore destroyed", 1, rec);

#ifdef HAVE_REGEX_H
	if (rec->regexp_compiled) regfree(&rec->preg);
#endif
	if (rec->time_tag > 0) g_source_remove(rec->time_tag);
	if (rec->channels != NULL) g_strfreev(rec->channels);
	g_free_not_null(rec->mask);
	g_free_not_null(rec->servertag);
	g_free_not_null(rec->pattern);
	g_free(rec);
}

void ignore_update_rec(IGNORE_REC *rec)
{
	if (rec->level == 0 && rec->except_level == 0) {
		/* unignored everything */
		ignore_remove_config(rec);
		ignore_destroy(rec);
	} else {
		/* unignore just some levels.. */
		ignore_remove_config(rec);
		ignores = g_slist_remove(ignores, rec);

		ignores = g_slist_append(ignores, rec);
		ignore_set_config(rec);

		signal_emit("ignore changed", 1, rec);
	}
}

static void read_ignores(void)
{
	IGNORE_REC *rec;
	CONFIG_NODE *node;
	GSList *tmp;

	while (ignores != NULL)
                ignore_destroy(ignores->data);

	node = iconfig_node_traverse("ignores", FALSE);
	if (node == NULL) return;

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		rec = g_new0(IGNORE_REC, 1);
		ignores = g_slist_append(ignores, rec);

		rec->mask = g_strdup(config_node_get_str(node, "mask", NULL));
		rec->pattern = g_strdup(config_node_get_str(node, "pattern", NULL));
		rec->level = level2bits(config_node_get_str(node, "level", ""));
		rec->except_level = level2bits(config_node_get_str(node, "except_level", ""));
		rec->regexp = config_node_get_bool(node, "regexp", FALSE);
		rec->fullword = config_node_get_bool(node, "fullword", FALSE);
		rec->replies = config_node_get_bool(node, "replies", FALSE);

		node = config_node_section(node, "channels", -1);
		if (node != NULL) rec->channels = config_node_get_list(node);
	}
}

void ignore_init(void)
{
	ignores = NULL;

        read_ignores();
        signal_add("setup reread", (SIGNAL_FUNC) read_ignores);
}

void ignore_deinit(void)
{
	while (ignores != NULL)
                ignore_destroy(ignores->data);

	signal_remove("setup reread", (SIGNAL_FUNC) read_ignores);
}
