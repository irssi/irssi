/*
 nicklist.c : irssi

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

#include "servers.h"
#include "channels.h"
#include "nicklist.h"
#include "masks.h"

#define isalnumhigh(a) \
        (isalnum(a) || (unsigned char) (a) >= 128)

/* Add new nick to list */
NICK_REC *nicklist_insert(CHANNEL_REC *channel, const char *nick,
			  int op, int voice, int send_massjoin)
{
	NICK_REC *rec;

	g_return_val_if_fail(IS_CHANNEL(channel), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(NICK_REC, 1);

	MODULE_DATA_INIT(rec);
	rec->type = module_get_uniq_id("NICK", 0);
        rec->chat_type = channel->chat_type;

	if (op) rec->op = TRUE;
	if (voice) rec->voice = TRUE;

	rec->send_massjoin = send_massjoin;
	rec->nick = g_strdup(nick);
	rec->host = NULL;

	g_hash_table_insert(channel->nicks, rec->nick, rec);
	signal_emit("nicklist new", 2, channel, rec);
	return rec;
}

static void nicklist_destroy(CHANNEL_REC *channel, NICK_REC *nick)
{
	signal_emit("nicklist remove", 2, channel, nick);

	g_free(nick->nick);
	g_free_not_null(nick->realname);
	g_free_not_null(nick->host);
	g_free(nick);
}

/* Remove nick from list */
void nicklist_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	g_return_if_fail(IS_CHANNEL(channel));
	g_return_if_fail(nick != NULL);

	g_hash_table_remove(channel->nicks, nick->nick);
	nicklist_destroy(channel, nick);
}

/* Change nick */
void nicklist_rename(SERVER_REC *server, const char *old_nick,
		     const char *new_nick)
{
	CHANNEL_REC *channel;
	NICK_REC *nickrec;
	GSList *nicks, *tmp;

	nicks = nicklist_get_same(server, old_nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		channel = tmp->data;
		nickrec = tmp->next->data;

		/* remove old nick from hash table */
		g_hash_table_remove(channel->nicks, nickrec->nick);

		g_free(nickrec->nick);
		nickrec->nick = g_strdup(new_nick);

		/* add new nick to hash table */
		g_hash_table_insert(channel->nicks, nickrec->nick, nickrec);

		signal_emit("nicklist changed", 3, channel, nickrec, old_nick);
	}
	g_slist_free(nicks);
}

static NICK_REC *nicklist_find_wildcards(CHANNEL_REC *channel,
					 const char *mask)
{
	GSList *nicks, *tmp;
	NICK_REC *nick;

	nicks = nicklist_getnicks(channel);
	nick = NULL;
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		nick = tmp->data;

		if (mask_match_address(channel->server, mask,
				       nick->nick, nick->host))
			break;
	}
	g_slist_free(nicks);
	return tmp == NULL ? NULL : nick;
}

GSList *nicklist_find_multiple(CHANNEL_REC *channel, const char *mask)
{
	GSList *nicks, *tmp, *next;

	g_return_val_if_fail(IS_CHANNEL(channel), NULL);
	g_return_val_if_fail(mask != NULL, NULL);

	nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = next) {
		NICK_REC *nick = tmp->data;

		next = tmp->next;
		if (!mask_match_address(channel->server, mask,
					nick->nick, nick->host))
                        nicks = g_slist_remove(nicks, tmp->data);
	}

	return nicks;
}

/* Find nick record from list */
NICK_REC *nicklist_find(CHANNEL_REC *channel, const char *mask)
{
	NICK_REC *nickrec;
	char *nick, *host;

	g_return_val_if_fail(IS_CHANNEL(channel), NULL);
	g_return_val_if_fail(mask != NULL, NULL);

	nick = g_strdup(mask);
	host = strchr(nick, '!');
	if (host != NULL) *host++ = '\0';

	if (strchr(nick, '*') || strchr(nick, '?')) {
		g_free(nick);
		return nicklist_find_wildcards(channel, mask);
	}

	nickrec = g_hash_table_lookup(channel->nicks, nick);

	if (nickrec != NULL && host != NULL &&
	    (nickrec->host == NULL || !match_wildcards(host, nickrec->host))) {
                /* hosts didn't match */
		nickrec = NULL;
	}
	g_free(nick);
	return nickrec;
}

static void get_nicks_hash(gpointer key, NICK_REC *rec, GSList **list)
{
	*list = g_slist_append(*list, rec);
}

/* Get list of nicks */
GSList *nicklist_getnicks(CHANNEL_REC *channel)
{
	GSList *list;

	g_return_val_if_fail(IS_CHANNEL(channel), NULL);

	list = NULL;
	g_hash_table_foreach(channel->nicks, (GHFunc) get_nicks_hash, &list);
	return list;
}

typedef struct {
        CHANNEL_REC *channel;
	const char *nick;
	GSList *list;
} NICKLIST_GET_SAME_REC;

static void get_nicks_same_hash(gpointer key, NICK_REC *nick,
				NICKLIST_GET_SAME_REC *rec)
{
	if (g_strcasecmp(nick->nick, rec->nick) == 0) {
		rec->list = g_slist_append(rec->list, rec->channel);
		rec->list = g_slist_append(rec->list, nick);
	}
}

GSList *nicklist_get_same(SERVER_REC *server, const char *nick)
{
	NICKLIST_GET_SAME_REC rec;
	GSList *tmp;

	g_return_val_if_fail(IS_SERVER(server), NULL);

	rec.nick = nick;
	rec.list = NULL;
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		rec.channel = tmp->data;
		g_hash_table_foreach(rec.channel->nicks,
				     (GHFunc) get_nicks_same_hash, &rec);
	}
	return rec.list;
}

/* nick record comparision for sort functions */
int nicklist_compare(NICK_REC *p1, NICK_REC *p2)
{
	if (p1 == NULL) return -1;
	if (p2 == NULL) return 1;

	if (p1->op && !p2->op) return -1;
	if (!p1->op && p2->op) return 1;

	if (!p1->op) {
		if (p1->voice && !p2->voice) return -1;
		if (!p1->voice && p2->voice) return 1;
	}

	return g_strcasecmp(p1->nick, p2->nick);
}

void nicklist_update_flags(SERVER_REC *server, const char *nick,
			   int gone, int serverop)
{
	GSList *nicks, *tmp;
	CHANNEL_REC *channel;
	NICK_REC *rec;

	g_return_if_fail(IS_SERVER(server));
	g_return_if_fail(nick != NULL);

	nicks = nicklist_get_same(server, nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		channel = tmp->data;
		rec = tmp->next->data;

		rec->last_check = time(NULL);

		if (gone != -1 && (int)rec->gone != gone) {
			rec->gone = gone;
			signal_emit("nick gone changed", 2, channel, rec);
		}

		if (serverop != -1 && (int)rec->serverop != serverop) {
			rec->serverop = serverop;
			signal_emit("nick serverop changed", 2, channel, rec);
		}
	}
	g_slist_free(nicks);
}

static void sig_channel_created(CHANNEL_REC *channel)
{
	g_return_if_fail(IS_CHANNEL(channel));

	channel->nicks = g_hash_table_new((GHashFunc) g_istr_hash,
					  (GCompareFunc) g_istr_equal);
}

static void nicklist_remove_hash(gpointer key, NICK_REC *nick,
				 CHANNEL_REC *channel)
{
	nicklist_destroy(channel, nick);
}

static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	g_return_if_fail(IS_CHANNEL(channel));

	g_hash_table_foreach(channel->nicks,
			     (GHFunc) nicklist_remove_hash, channel);
	g_hash_table_destroy(channel->nicks);
}

static NICK_REC *nick_nfind(CHANNEL_REC *channel, const char *nick, int len)
{
        NICK_REC *rec;
	char *tmpnick;

	tmpnick = g_strndup(nick, len);
	rec = g_hash_table_lookup(channel->nicks, tmpnick);
        g_free(tmpnick);
	return rec;
}

/* Check is `msg' is meant for `nick'. */
int nick_match_msg(CHANNEL_REC *channel, const char *msg, const char *nick)
{
	const char *msgstart, *orignick;
	int len, fullmatch;

	g_return_val_if_fail(nick != NULL, FALSE);
	g_return_val_if_fail(msg != NULL, FALSE);

	if (channel != NULL && channel->server->nick_match_msg != NULL)
		return channel->server->nick_match_msg(msg, nick);

	/* first check for identical match */
	len = strlen(nick);
	if (g_strncasecmp(msg, nick, len) == 0 && !isalnumhigh((int) msg[len]))
		return TRUE;

	orignick = nick;
	for (;;) {
		nick = orignick;
		msgstart = msg;
                fullmatch = TRUE;

		/* check if it matches for alphanumeric parts of nick */
		while (*nick != '\0' && *msg != '\0') {
			if (toupper(*nick) == toupper(*msg)) {
				/* total match */
				msg++;
			} else if (isalnum(*msg) && !isalnum(*nick)) {
				/* some strange char in your nick, pass it */
                                fullmatch = FALSE;
			} else
				break;

			nick++;
		}

		if (msg != msgstart && !isalnumhigh(*msg)) {
			/* at least some of the chars in line matched the
			   nick, and msg continue with non-alphanum character,
			   this might be for us.. */
			if (*nick != '\0') {
				/* remove the rest of the non-alphanum chars
				   from nick and check if it then matches. */
                                fullmatch = FALSE;
				while (*nick != '\0' && !isalnum(*nick))
					nick++;
			}

			if (*nick == '\0') {
				/* yes, match! */
                                break;
			}
		}

		/* no match. check if this is a message to multiple people
		   (like nick1,nick2: text) */
		while (*msg != '\0' && *msg != ' ' && *msg != ',') msg++;

		if (*msg != ',') {
                        nick = orignick;
			break;
		}

                msg++;
	}

	if (*nick != '\0')
		return FALSE; /* didn't match */

	if (fullmatch)
		return TRUE; /* matched without fuzzyness */

	/* matched with some fuzzyness .. check if there's an exact match
	   for some other nick in the same channel. */
        return nick_nfind(channel, msgstart, (int) (msg-msgstart)) == NULL;
}

void nicklist_init(void)
{
	signal_add_first("channel created", (SIGNAL_FUNC) sig_channel_created);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}

void nicklist_deinit(void)
{
	signal_remove("channel created", (SIGNAL_FUNC) sig_channel_created);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	module_uniq_destroy("NICK");
}
