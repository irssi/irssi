/*
 irc-nicklist.c : irssi

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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-masks.h>
#include <irssi/src/irc/core/irc-nicklist.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/core/servers.h>

static void nicklist_set_modes(IRC_CHANNEL_REC *channel, NICK_REC *rec, gboolean op,
                               gboolean halfop, gboolean voice, const char *prefixes,
                               gboolean send_changed)
{
	gboolean changed = FALSE;
	if (rec->op != op) {
		rec->op = op;
		changed = TRUE;
	}
	if (rec->halfop != halfop) {
		rec->halfop = halfop;
		changed = TRUE;
	}
	if (rec->voice != voice) {
		rec->voice = voice;
		changed = TRUE;
	}

	if (prefixes != NULL && g_strcmp0(rec->prefixes, prefixes) != 0) {
		g_strlcpy(rec->prefixes, prefixes, sizeof(rec->prefixes));
		changed = TRUE;
	}

	if (changed && send_changed) {
		signal_emit("nicklist changed", 3, channel, rec, rec->nick);
	}
}

/* Add new nick to list */
NICK_REC *irc_nicklist_insert(IRC_CHANNEL_REC *channel, const char *nick,
			      int op, int halfop, int voice, int send_massjoin,
			      const char *prefixes)
{
	NICK_REC *rec;

	g_return_val_if_fail(IS_IRC_CHANNEL(channel), NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec = g_new0(NICK_REC, 1);
	rec->nick = g_strdup(nick);

	rec->send_massjoin = send_massjoin;
	nicklist_set_modes(channel, rec, op, halfop, voice, prefixes, FALSE);

	nicklist_insert(CHANNEL(channel), rec);
	return rec;
}

int irc_nickcmp_rfc1459(const char *m, const char *n)
{
	while (*m != '\0' && *n != '\0') {
		if (to_rfc1459(*m) != to_rfc1459(*n))
			return -1;
		m++; n++;
	}
	return *m == *n ? 0 : 1;
}

int irc_nickcmp_ascii(const char *m, const char *n)
{
	while (*m != '\0' && *n != '\0') {
		if (to_ascii(*m) != to_ascii(*n))
			return -1;
		m++; n++;
	}
	return *m == *n ? 0 : 1;
}

static void event_names_list(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *rec;
	char *params, *type, *channel, *names, *ptr, *host;
        int op, halfop, voice;
	char prefixes[MAX_USER_PREFIXES+1];
	const char *nick_flags, *nick_flag_cur, *nick_flag_op;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &type, &channel, &names);

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL || chanrec->names_got) {
		/* unknown channel / names list already read */
		g_free(params);
		return;
	}
	nick_flags = server->get_nick_flags(SERVER(server));
	nick_flag_op = strchr(nick_flags, '@');

	/* type = '=' = public, '*' = private, '@' = secret.

	   This is actually pretty useless to check here, but at least we
	   get to know if the channel is +p or +s a few seconds before
	   we receive the MODE reply...

	   If the channel key is set, assume the channel is +k also until
           we know better, so parse_channel_modes() won't clear the key */
	if (*type == '*') {
		parse_channel_modes(chanrec, NULL,
				    chanrec->key ? "+kp" : "+p", FALSE);
	} else if (*type == '@') {
		parse_channel_modes(chanrec, NULL,
				    chanrec->key ? "+ks" : "+s", FALSE);
	}

	while (*names != '\0') {
		while (*names == ' ') names++;
		ptr = names;
		while (*names != '\0' && *names != ' ') names++;
		if (*names != '\0') *names++ = '\0';

		/* some servers show ".@nick", there's also been talk about
		   showing "@+nick" and since none of these chars are valid
		   nick chars, just check them until a non-nickflag char is
		   found. */
		op = halfop = voice = FALSE;
		prefixes[0] = '\0';
		while (isnickflag(server, *ptr)) {
			prefix_add(prefixes, *ptr, (SERVER_REC *) server);
			switch (*ptr) {
			case '@':
                                op = TRUE;
                                break;
			case '%':
                                halfop = TRUE;
                                break;
			case '+':
                                voice = TRUE;
                                break;
			default:
				/* If this flag is listed higher than op (in the
				 * isupport PREFIX reply), then count this user
				 * as an op. */
				nick_flag_cur = strchr(nick_flags, *ptr);
				if (nick_flag_cur && nick_flag_op && nick_flag_cur < nick_flag_op) {
					op = TRUE;
				}
				break;
			}
                        ptr++;
		}

		host = strchr(ptr, '!');
		if (host != NULL)
			*host++ = '\0';

		rec = nicklist_find((CHANNEL_REC *) chanrec, ptr);
		if (rec == NULL) {
			rec = irc_nicklist_insert(chanrec, ptr, op, halfop,
						  voice, FALSE, prefixes);
			if (host != NULL)
				nicklist_set_host(CHANNEL(chanrec), rec, host);
		} else {
			nicklist_set_modes(chanrec, rec, op, halfop, voice, prefixes, TRUE);
		}
	}

	g_free(params);
}

static void event_end_of_names(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;
	IRC_CHANNEL_REC *chanrec;
	NICK_REC *ownnick;
	int nicks;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL && !chanrec->names_got) {
		ownnick = nicklist_find(CHANNEL(chanrec), server->nick);
		if (ownnick == NULL) {
			/* stupid server - assume we have ops
			   if channel is empty */
			nicks = g_hash_table_size(chanrec->nicks);
			ownnick = irc_nicklist_insert(chanrec, server->nick,
						      nicks == 0, FALSE,
						      FALSE, FALSE, NULL);
		}
		nicklist_set_own(CHANNEL(chanrec), ownnick);
                chanrec->chanop = chanrec->ownnick->op;
		chanrec->names_got = TRUE;
		signal_emit("channel joined", 1, chanrec);
	}

	g_free(params);
}

static void fill_who(SERVER_REC *server, const char *channel, const char *user, const char *host,
                     const char *nick, const char *stat, const char *hops, const char *account,
                     const char *realname)
{
	CHANNEL_REC *chanrec;
	NICK_REC *nickrec;

	/* update host, realname, hopcount */
	chanrec = channel_find(server, channel);
	nickrec = chanrec == NULL ? NULL :
		nicklist_find(chanrec, nick);
	if (nickrec != NULL) {
		if (nickrec->host == NULL) {
                        char *str = g_strdup_printf("%s@%s", user, host);
			nicklist_set_host(chanrec, nickrec, str);
                        g_free(str);
		}
		if (nickrec->realname == NULL) {
			nickrec->realname = g_strdup(realname);
		}
		if (nickrec->account == NULL && account != NULL) {
			nicklist_set_account(chanrec, nickrec,
			                     strcmp(account, "0") == 0 ? "*" : account);
		}
		sscanf(hops, "%d", &nickrec->hops);
	}

	nicklist_update_flags(server, nick,
			      strchr(stat, 'G') != NULL, /* gone */
			      strchr(stat, '*') != NULL); /* ircop */
}

static void event_who(SERVER_REC *server, const char *data)
{
	char *params, *nick, *channel, *user, *host, *stat, *realname, *hops;

	g_return_if_fail(data != NULL);

	params =
	    event_get_params(data, 8, NULL, &channel, &user, &host, NULL, &nick, &stat, &realname);

	/* get hop count */
	hops = realname;
	while (*realname != '\0' && *realname != ' ')
		realname++;
	if (*realname == ' ')
		*realname++ = '\0';

	fill_who(server, channel, user, host, nick, stat, hops, NULL, realname);

	g_free(params);
}

static void event_whox_channel_full(SERVER_REC *server, const char *data)
{
	char *params, *id, *nick, *channel, *user, *host, *stat, *hops, *account, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 10, NULL, &id, &channel, &user, &host, &nick, &stat, &hops,
	                          &account, &realname);

	if (g_strcmp0(id, WHOX_CHANNEL_FULL_ID) != 0) {
		g_free(params);
		return;
	}

	fill_who(server, channel, user, host, nick, stat, hops, account, realname);

	g_free(params);
}

static void event_whox_useraccount(IRC_SERVER_REC *server, const char *data)
{
	char *params, *id, *nick, *account;
	GSList *nicks, *tmp;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &id, &nick, &account);

	if (g_strcmp0(id, WHOX_USERACCOUNT_ID) != 0) {
		g_free(params);
		return;
	}
	g_hash_table_remove(server->chanqueries->accountqueries, nick);

	if (strcmp(account, "0") == 0) {
		account = "*";
	}

	nicks = nicklist_get_same(SERVER(server), nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		NICK_REC *rec = tmp->next->data;

		if (rec->account == NULL || g_strcmp0(rec->account, account) != 0) {
			nicklist_set_account(CHANNEL(tmp->data), rec, account);
		}
	}
	g_slist_free(nicks);
	g_free(params);
}

static void event_whois(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *realname;
	GSList *nicks, *tmp;
	NICK_REC *rec;

	g_return_if_fail(data != NULL);

	/* first remove the gone-flag, if user is gone
	   it will be set later.. */
	params = event_get_params(data, 6, NULL, &nick, NULL,
				  NULL, NULL, &realname);

	nicks = nicklist_get_same(SERVER(server), nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		rec = tmp->next->data;

		if (rec->realname == NULL)
			rec->realname = g_strdup(realname);
	}
	g_slist_free(nicks);

	/* reset gone and ircop status, we'll handle them in the following
	   WHOIS replies */
	nicklist_update_flags(SERVER(server), nick, FALSE, FALSE);
	g_free(params);
}

static void event_whois_away(SERVER_REC *server, const char *data)
{
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	nicklist_update_flags(server, nick, TRUE, -1);
	g_free(params);
}

static void event_own_away(SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 2, &nick, NULL);
	nicklist_update_flags(server, nick, TRUE, -1);
	g_free(params);
}

static void event_own_unaway(SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 2, &nick, NULL);
	nicklist_update_flags(server, nick, FALSE, -1);
	g_free(params);
}

static void event_whois_ircop(SERVER_REC *server, const char *data)
{
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	nicklist_update_flags(server, nick, -1, TRUE);
	g_free(params);
}

static void event_nick_invalid(IRC_SERVER_REC *server, const char *data)
{
	if (!server->connected)
		/* we used to call server_disconnect but that crashes
		   irssi because of undefined memory access. instead,
		   indicate that the connection should be dropped and
		   let the irc method to the clean-up. */
		server->connection_lost = server->no_reconnect = TRUE;
}

static void event_nick_in_use(IRC_SERVER_REC *server, const char *data)
{
	char *str, *cmd, *params, *nick;
	int n;
	gboolean try_alternate_nick;

	g_return_if_fail(data != NULL);

	if (server->connected) {
		/* Already connected, no need to handle this anymore. */
		return;
	}
	
	try_alternate_nick = g_ascii_strcasecmp(server->nick, server->connrec->nick) == 0 &&
	    server->connrec->alternate_nick != NULL &&
	    g_ascii_strcasecmp(server->connrec->alternate_nick, server->nick) != 0;

	params = event_get_params(data, 2, NULL, &nick);
	if (g_ascii_strcasecmp(server->nick, nick) != 0) {
		/* the server uses a nick different from the one we send */
		g_free(server->nick);
		server->nick = g_strdup(nick);
	}
	g_free(params);

	/* nick already in use - need to change it .. */
	if (try_alternate_nick) {
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

	cmd = g_strdup_printf("NICK %s", server->nick);
	irc_send_cmd_now(server, cmd);
	g_free(cmd);
}

static void event_target_unavailable(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	if (!server_ischannel(SERVER(server), channel)) {
		/* nick is unavailable. */
		event_nick_in_use(server, data);
	}

	g_free(params);
}

static void event_nick(IRC_SERVER_REC *server, const char *data,
		       const char *orignick)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);
	g_return_if_fail(orignick != NULL);

	params = event_get_params(data, 1, &nick);

	if (g_ascii_strcasecmp(orignick, server->nick) == 0) {
		/* You changed your nick */
		if (server->last_nick != NULL &&
		    g_ascii_strcasecmp(server->last_nick, nick) == 0) {
                        /* changed with /NICK - keep it as wanted nick */
			g_free(server->connrec->nick);
			server->connrec->nick = g_strdup(nick);
		}

		server_change_nick(SERVER(server), nick);
	}

	/* invalidate any outstanding accountqueries for the old nick */
	irc_channels_query_purge_accountquery(server, orignick);
	nicklist_rename(SERVER(server), orignick, nick);
	g_free(params);
}

static void event_userhost(SERVER_REC *server, const char *data)
{
	char *params, *hosts, **phosts, **pos, *ptr;
	int oper;

	g_return_if_fail(data != NULL);

	/* set user's gone flag.. */
	params = event_get_params(data, 2, NULL, &hosts);

	phosts = g_strsplit(hosts, " ", -1);
	for (pos = phosts; *pos != NULL; pos++) {
		ptr = strchr(*pos, '=');
		if (ptr == NULL || ptr == *pos) continue;
		if (ptr[-1] == '*') {
			ptr[-1] = '\0';
			oper = 1;
		} else
			oper = 0;
		*ptr++ = '\0';

		nicklist_update_flags(server, *pos, *ptr == '-', oper);
	}
	g_strfreev(phosts);
	g_free(params);
}

static void event_setname(SERVER_REC *server, const char *data, const char *nick, const char *address)
{
	GSList *nicks, *tmp;
	NICK_REC *rec;

	if (!IS_IRC_SERVER(server))
		return;

	g_return_if_fail(nick != NULL);
	g_return_if_fail(data != NULL);
	if (*data == ':') data++;

	nicks = nicklist_get_same(server, nick);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		rec = tmp->next->data;

		g_free(rec->realname);
		rec->realname = g_strdup(data);
	}
	g_slist_free(nicks);
}

static void event_away_notify(IRC_SERVER_REC *server, const char *data, const char *nick, const char *add)
{
	char *params, *awaymsg;

	if (!IS_IRC_SERVER(server))
		return;

	g_return_if_fail(nick != NULL);
	g_return_if_fail(data != NULL);

	params = event_get_params(data, 1 | PARAM_FLAG_GETREST, &awaymsg);
	nicklist_update_flags(SERVER(server), nick, *awaymsg != '\0', -1);
	g_free(params);
}

static void sig_usermode(SERVER_REC *server)
{
	g_return_if_fail(IS_SERVER(server));

	nicklist_update_flags(server, server->nick, server->usermode_away, -1);
}

static const char *get_nick_flags(SERVER_REC *server)
{
	IRC_SERVER_REC *irc_server = (IRC_SERVER_REC *) server;
	const char *prefix =
		g_hash_table_lookup(irc_server->isupport, "PREFIX");

	prefix = prefix == NULL ? NULL : strchr(prefix, ')');
	return prefix == NULL ? "" : prefix+1;
}

static void sig_connected(IRC_SERVER_REC *server)
{
	if (IS_IRC_SERVER(server))
		server->get_nick_flags = get_nick_flags;
}

void irc_nicklist_init(void)
{
	signal_add_first("event nick", (SIGNAL_FUNC) event_nick);
	signal_add_first("event 352", (SIGNAL_FUNC) event_who);
	signal_add_first("event 354", (SIGNAL_FUNC) event_whox_channel_full);
	signal_add("silent event who", (SIGNAL_FUNC) event_who);
	signal_add("silent event whox", (SIGNAL_FUNC) event_whox_channel_full);
	signal_add("silent event whox useraccount", (SIGNAL_FUNC) event_whox_useraccount);
	signal_add("silent event whois", (SIGNAL_FUNC) event_whois);
	signal_add_first("event 311", (SIGNAL_FUNC) event_whois);
	signal_add_first("whois away", (SIGNAL_FUNC) event_whois_away);
	signal_add_first("whois oper", (SIGNAL_FUNC) event_whois_ircop);
	signal_add_first("event 306", (SIGNAL_FUNC) event_own_away);
	signal_add_first("event 305", (SIGNAL_FUNC) event_own_unaway);
	signal_add_first("event 353", (SIGNAL_FUNC) event_names_list);
	signal_add_first("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_add_first("event 432", (SIGNAL_FUNC) event_nick_invalid);
	signal_add_first("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_add_first("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_add_first("event 302", (SIGNAL_FUNC) event_userhost);
	signal_add_first("event away", (SIGNAL_FUNC) event_away_notify);
	signal_add("userhost event", (SIGNAL_FUNC) event_userhost);
	signal_add("event setname", (SIGNAL_FUNC) event_setname);
	signal_add("user mode changed", (SIGNAL_FUNC) sig_usermode);
	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
}

void irc_nicklist_deinit(void)
{
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("event 352", (SIGNAL_FUNC) event_who);
	signal_remove("event 354", (SIGNAL_FUNC) event_whox_channel_full);
	signal_remove("silent event who", (SIGNAL_FUNC) event_who);
	signal_remove("silent event whox", (SIGNAL_FUNC) event_whox_channel_full);
	signal_remove("silent event whox useraccount", (SIGNAL_FUNC) event_whox_useraccount);
	signal_remove("silent event whois", (SIGNAL_FUNC) event_whois);
	signal_remove("event 311", (SIGNAL_FUNC) event_whois);
	signal_remove("whois away", (SIGNAL_FUNC) event_whois_away);
	signal_remove("whois oper", (SIGNAL_FUNC) event_whois_ircop);
	signal_remove("event 306", (SIGNAL_FUNC) event_own_away);
	signal_remove("event 305", (SIGNAL_FUNC) event_own_unaway);
	signal_remove("event 353", (SIGNAL_FUNC) event_names_list);
	signal_remove("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_remove("event 432", (SIGNAL_FUNC) event_nick_invalid);
	signal_remove("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_remove("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_remove("event 302", (SIGNAL_FUNC) event_userhost);
	signal_remove("event away", (SIGNAL_FUNC) event_away_notify);
	signal_remove("userhost event", (SIGNAL_FUNC) event_userhost);
	signal_remove("event setname", (SIGNAL_FUNC) event_setname);
	signal_remove("user mode changed", (SIGNAL_FUNC) sig_usermode);
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
}
