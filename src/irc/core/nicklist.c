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

#include "channels.h"
#include "irc.h"
#include "masks.h"
#include "modes.h"
#include "nicklist.h"
#include "irc-server.h"

/* Add new nick to list */
NICK_REC *nicklist_insert(CHANNEL_REC *channel, const char *nick,
			  int op, int voice, int send_massjoin)
{
	NICK_REC *rec;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(NICK_REC, 1);

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

/* remove nick from list */
void nicklist_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	g_return_if_fail(channel != NULL);
	g_return_if_fail(nick != NULL);

	g_hash_table_remove(channel->nicks, nick->nick);
	nicklist_destroy(channel, nick);
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

		if (irc_mask_match_address(mask, nick->nick, nick->host))
			break;
	}
	g_slist_free(nicks);
	return tmp == NULL ? NULL : nick;
}

GSList *nicklist_find_multiple(CHANNEL_REC *channel, const char *mask)
{
	GSList *nicks, *tmp, *next;

	nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = next) {
		NICK_REC *nick = tmp->data;

		next = tmp->next;
		if (!irc_mask_match_address(mask, nick->nick, nick->host))
                        nicks = g_slist_remove(nicks, tmp->data);
	}

	return nicks;
}

/* Find nick record from list */
NICK_REC *nicklist_find(CHANNEL_REC *channel, const char *mask)
{
	NICK_REC *nickrec;
	char *nick, *host;

	g_return_val_if_fail(channel != NULL, NULL);
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

	list = NULL;
	g_hash_table_foreach(channel->nicks, (GHFunc) get_nicks_hash, &list);
	return list;
}

typedef struct {
        CHANNEL_REC *channel;
	const char *nick;
	GSList *list;
} NICKLIST_GET_SAME_REC;

static void get_nicks_same_hash(gpointer key, NICK_REC *nick, NICKLIST_GET_SAME_REC *rec)
{
	if (g_strcasecmp(nick->nick, rec->nick) == 0) {
		rec->list = g_slist_append(rec->list, rec->channel);
		rec->list = g_slist_append(rec->list, nick);
	}
}

GSList *nicklist_get_same(IRC_SERVER_REC *server, const char *nick)
{
	NICKLIST_GET_SAME_REC rec;
	GSList *tmp;

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

#define isnickchar(a) \
    (isalnum(a) || (a) == '`' || (a) == '-' || (a) == '_' || \
    (a) == '[' || (a) == ']' || (a) == '{' || (a) == '}' || \
    (a) == '|' || (a) == '\\' || (a) == '^')

/* Remove all "extra" characters from `nick'. Like _nick_ -> nick */
char *nick_strip(const char *nick)
{
	char *stripped, *spos;

	g_return_val_if_fail(nick != NULL, NULL);

	spos = stripped = g_strdup(nick);
	while (isnickchar(*nick)) {
		if (isalnum((gint) *nick)) *spos++ = *nick;
		nick++;
	}
	if ((unsigned char) *nick >= 128)
		*spos++ = *nick; /* just add it so that nicks won't match.. */
	*spos = '\0';
	return stripped;
}

/* Check is `msg' is meant for `nick'. */
int irc_nick_match(const char *nick, const char *msg)
{
	char *stripnick, *stripmsg;
	int ret, len;

	g_return_val_if_fail(nick != NULL, FALSE);
	g_return_val_if_fail(msg != NULL, FALSE);

	len = strlen(nick);
	if (g_strncasecmp(msg, nick, len) == 0 && !isalnum((int) msg[len]))
		return TRUE;

	stripnick = nick_strip(nick);
	stripmsg = nick_strip(msg);

	len = strlen(stripnick);
	ret = len > 0 && g_strncasecmp(stripmsg, stripnick, len) == 0 &&
		!isalnum((int) stripmsg[len]) &&
		(unsigned char) stripmsg[len] < 128;

	g_free(stripnick);
	g_free(stripmsg);
	return ret;
}

static void event_names_list(const char *data, IRC_SERVER_REC *server)
{
	CHANNEL_REC *chanrec;
	char *params, *type, *channel, *names, *ptr;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &type, &channel, &names);

	chanrec = channel_find(server, channel);
	if (chanrec == NULL || chanrec->names_got) {
		/* unknown channel / names list already read */
		g_free(params);
		return;
	}

	/* type = '=' = public, '*' = private, '@' = secret.

	   This is actually pretty useless to check here, but at least we
	   get to know if the channel is +p or +s a few seconds before
	   we receive the MODE reply... */
	if (*type == '*')
		parse_channel_modes(chanrec, NULL, "+p");
	else if (*type == '@')
		parse_channel_modes(chanrec, NULL, "+s");

	while (*names != '\0') {
		while (*names == ' ') names++;
		ptr = names;
		while (*names != '\0' && *names != ' ') names++;
		if (*names != '\0') *names++ = '\0';

		if (*ptr == '@' && g_strcasecmp(server->nick, ptr+1) == 0)
			chanrec->chanop = TRUE;

		nicklist_insert(chanrec, ptr+isnickflag(*ptr),
				*ptr == '@', *ptr == '+', FALSE);
	}

	g_free(params);
}

static void event_end_of_names(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;
	CHANNEL_REC *chanrec;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = channel_find(server, channel);
	if (chanrec != NULL && !chanrec->names_got) {
		chanrec->names_got = TRUE;
		signal_emit("channel query", 1, chanrec);
	}

	g_free(params);
}

static void nicklist_update_flags(IRC_SERVER_REC *server, const char *nick,
				  int gone, int ircop)
{
	GSList *nicks, *tmp;
	CHANNEL_REC *channel;
	NICK_REC *rec;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	nicks = nicklist_get_same(server, nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		channel = tmp->data;
		rec = tmp->next->data;

		rec->last_check = time(NULL);

		if (gone != -1 && rec->gone != gone) {
			rec->gone = gone;
			signal_emit("nick gone changed", 2, channel, rec);
		}

		if (ircop != -1 && rec->ircop != ircop) {
			rec->ircop = ircop;
			signal_emit("nick ircop changed", 2, channel, rec);
		}
	}
	g_slist_free(nicks);
}

static void event_who(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *channel, *user, *host, *stat, *realname, *hops;
	CHANNEL_REC *chanrec;
	NICK_REC *nickrec;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 8, NULL, &channel, &user, &host,
				  NULL, &nick, &stat, &realname);

	/* get hop count */
	hops = realname;
	while (*realname != '\0' && *realname != ' ') realname++;
	*realname++ = '\0';
	while (*realname == ' ') realname++;

	/* update host, realname, hopcount */
	chanrec = channel_find(server, channel);
	nickrec = chanrec == NULL ? NULL : nicklist_find(chanrec, nick);
	if (nickrec != NULL) {
		if (nickrec->host == NULL)
			nickrec->host = g_strdup_printf("%s@%s", user, host);
		if (nickrec->realname == NULL)
			nickrec->realname = g_strdup(realname);
		sscanf(hops, "%d", &nickrec->hops);
	}

	nicklist_update_flags(server, nick,
			      strchr(stat, 'G') != NULL, /* gone */
			      strchr(stat, '*') != NULL); /* ircop */

	g_free(params);
}

static void event_whois(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *realname;
	GSList *nicks, *tmp;
	NICK_REC *rec;

	g_return_if_fail(data != NULL);

	server->whois_coming = TRUE;

	/* first remove the gone-flag, if user is gone
	   it will be set later.. */
	params = event_get_params(data, 6, NULL, &nick, NULL,
				  NULL, NULL, &realname);

	nicks = nicklist_get_same(server, nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		rec = tmp->next->data;

		if (rec->realname == NULL)
			rec->realname = g_strdup(realname);
	}
	g_slist_free(nicks);

	/* reset gone and ircop status, we'll handle them in the following
	   WHOIS replies */
	nicklist_update_flags(server, nick, FALSE, FALSE);
	g_free(params);
}

static void event_whois_away(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	nicklist_update_flags(server, nick, TRUE, -1);
	g_free(params);
}

static void event_whois_ircop(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	nicklist_update_flags(server, nick, -1, TRUE);
	g_free(params);
}

static void event_end_of_whois(const char *data, IRC_SERVER_REC *server)
{
	server->whois_coming = FALSE;
}

static void event_nick_in_use(const char *data, IRC_SERVER_REC *server)
{
	char *str;
	int n;

	g_return_if_fail(data != NULL);

	if (server->connected) {
		/* Already connected, no need to handle this anymore. */
		return;
	}

	/* nick already in use - need to change it .. */
	if (strcmp(server->nick, server->connrec->nick) == 0 &&
	    server->connrec->alternate_nick != NULL) {
		/* first try, so try the alternative nick.. */
		g_free(server->nick);
		server->nick = g_strdup(server->connrec->alternate_nick);
	}
	else if (strlen(server->nick) < 9) {
		/* keep adding '_' to end of nick.. */
		str = g_strdup_printf("%s_", server->nick);
		g_free(server->nick);
		server->nick = str;
	} else {
		/* nick full, keep adding number at the end */
		for (n = 8; n > 0; n--) {
			if (server->nick[n] < '0' || server->nick[n] > '9') {
				server->nick[n] = '1';
				break;
			}

			if (server->nick[n] < '9') {
				server->nick[n]++;
				break;
			}
			server->nick[n] = '0';
		}
	}

	irc_send_cmdv(server, "NICK %s", server->nick);
}

static void event_target_unavailable(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	if (!ischannel(*channel)) {
		/* nick is unavailable. */
		event_nick_in_use(data, server);
	}

	g_free(params);
}

static void event_nick(const char *data, IRC_SERVER_REC *server,
		       const char *orignick)
{
	CHANNEL_REC *channel;
	NICK_REC *nickrec;
	GSList *nicks, *tmp;
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1, &nick);

	if (g_strcasecmp(orignick, server->nick) == 0) {
		/* You changed your nick */
		g_free(server->connrec->nick);
		g_free(server->nick);
		server->connrec->nick = g_strdup(nick);
		server->nick = g_strdup(nick);
		signal_emit("server nick changed", 1, server);
	}

	nicks = nicklist_get_same(server, orignick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		channel = tmp->data;
		nickrec = tmp->next->data;

		/* remove old nick from hash table */
		g_hash_table_remove(channel->nicks, nickrec->nick);

		g_free(nickrec->nick);
		nickrec->nick = g_strdup(nick);

		/* add new nick to hash table */
		g_hash_table_insert(channel->nicks, nickrec->nick, nickrec);

		signal_emit("nicklist changed", 3, channel, nickrec, orignick);
	}
	g_slist_free(nicks);

	g_free(params);
}

static void event_userhost(const char *data, IRC_SERVER_REC *server)
{
	char *params, *hosts, **phosts, **pos, *ptr;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 2, NULL, &hosts);

	phosts = g_strsplit(hosts, " ", -1);
	for (pos = phosts; *pos != NULL; pos++) {
		ptr = strchr(*pos, '=');
		if (ptr == NULL) continue;
		*ptr++ = '\0';

		nicklist_update_flags(server, *pos, *ptr == '-', -1);
	}
	g_strfreev(phosts);
	g_free(params);
}

static void sig_usermode(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	nicklist_update_flags(server, server->nick, server->usermode_away, -1);
}

static void sig_channel_created(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

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
	g_return_if_fail(channel != NULL);

	g_hash_table_foreach(channel->nicks,
			     (GHFunc) nicklist_remove_hash, channel);
	g_hash_table_destroy(channel->nicks);
}

void nicklist_init(void)
{
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
	signal_add_first("event 352", (SIGNAL_FUNC) event_who);
	signal_add("silent event who", (SIGNAL_FUNC) event_who);
	signal_add("silent event whois", (SIGNAL_FUNC) event_whois);
	signal_add_first("event 311", (SIGNAL_FUNC) event_whois);
	signal_add_first("event 301", (SIGNAL_FUNC) event_whois_away);
	signal_add_first("event 313", (SIGNAL_FUNC) event_whois_ircop);
	signal_add("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_add("event 353", (SIGNAL_FUNC) event_names_list);
	signal_add("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_add("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_add("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_add("event 302", (SIGNAL_FUNC) event_userhost);
	signal_add("userhost event", (SIGNAL_FUNC) event_userhost);
	signal_add("user mode changed", (SIGNAL_FUNC) sig_usermode);
	signal_add_first("channel created", (SIGNAL_FUNC) sig_channel_created);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}

void nicklist_deinit(void)
{
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("event 352", (SIGNAL_FUNC) event_who);
	signal_remove("silent event who", (SIGNAL_FUNC) event_who);
	signal_remove("silent event whois", (SIGNAL_FUNC) event_whois);
	signal_remove("event 311", (SIGNAL_FUNC) event_whois);
	signal_remove("event 301", (SIGNAL_FUNC) event_whois_away);
	signal_remove("event 313", (SIGNAL_FUNC) event_whois_ircop);
	signal_remove("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_remove("event 353", (SIGNAL_FUNC) event_names_list);
	signal_remove("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_remove("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_remove("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_remove("event 302", (SIGNAL_FUNC) event_userhost);
	signal_remove("userhost event", (SIGNAL_FUNC) event_userhost);
	signal_remove("user mode changed", (SIGNAL_FUNC) sig_usermode);
	signal_remove("channel created", (SIGNAL_FUNC) sig_channel_created);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}
