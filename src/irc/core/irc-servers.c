/*
 irc-server.c : irssi

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

#include "net-sendbuffer.h"
#include "signals.h"
#include "rawlog.h"
#include "misc.h"

#include "channels.h"
#include "queries.h"

#include "irc-nicklist.h"
#include "irc-queries.h"
#include "irc-servers-setup.h"
#include "irc-servers.h"
#include "channel-rejoin.h"
#include "servers-idle.h"
#include "servers-reconnect.h"
#include "servers-redirect.h"
#include "modes.h"

#include "settings.h"
#include "recode.h"

#define DEFAULT_MAX_KICKS 1
#define DEFAULT_MAX_MODES 3
#define DEFAULT_MAX_WHOIS 4
#define DEFAULT_MAX_MSGS 1

#define DEFAULT_USER_MODE "+i"
#define DEFAULT_CMD_QUEUE_SPEED "2200msec"
#define DEFAULT_CMDS_MAX_AT_ONCE 5
#define DEFAULT_MAX_QUERY_CHANS 1 /* more and more IRC networks are using stupid ircds.. */

void irc_servers_reconnect_init(void);
void irc_servers_reconnect_deinit(void);

static int cmd_tag;

static int isnickflag_func(SERVER_REC *server, char flag)
{
	IRC_SERVER_REC *irc_server = (IRC_SERVER_REC *) server;

	return isnickflag(irc_server, flag);
}

static int ischannel_func(SERVER_REC *server, const char *data)
{
	if (*data == '@') {
		/* @#channel, @+#channel */
		data++;
		if (*data == '+' && ischannel(data[1]))
			return 1;
	}
	return ischannel(*data);
}

static void send_message(SERVER_REC *server, const char *target,
			 const char *msg, int target_type)
{
	IRC_SERVER_REC *ircserver;
	CHANNEL_REC *channel;
	char *str;
	char *recoded;

        ircserver = IRC_SERVER(server);
	g_return_if_fail(ircserver != NULL);
	g_return_if_fail(target != NULL);
	g_return_if_fail(msg != NULL);

	if (*target == '!') {
		/* !chan -> !12345chan */
		channel = channel_find(server, target);
		if (channel != NULL && g_strcasecmp(channel->name, target) != 0)
			target = channel->name;
	}

	recoded = recode_out(SERVER(server), msg, target);
	str = g_strdup_printf("PRIVMSG %s :%s", target, recoded);
	irc_send_cmd_split(ircserver, str, 2, ircserver->max_msgs_in_cmd);
	g_free(str);
	g_free(recoded);
}

static void server_init(IRC_SERVER_REC *server)
{
	IRC_SERVER_CONNECT_REC *conn;
	char *address, *ptr, *username, *cmd;
	GTimeVal now;

	g_return_if_fail(server != NULL);

	conn = server->connrec;

	if (conn->proxy != NULL && conn->proxy_password != NULL &&
	    *conn->proxy_password != '\0') {
		cmd = g_strdup_printf("PASS %s", conn->proxy_password);
		irc_send_cmd_now(server, cmd);
		g_free(cmd);
	}

	if (conn->proxy != NULL && conn->proxy_string != NULL) {
		cmd = g_strdup_printf(conn->proxy_string, conn->address, conn->port);
		irc_send_cmd_now(server, cmd);
		g_free(cmd);
	}

	if (conn->password != NULL && *conn->password != '\0') {
                /* send password */
		cmd = g_strdup_printf("PASS %s", conn->password);
		irc_send_cmd_now(server, cmd);
		g_free(cmd);
	}

        /* send nick */
	cmd = g_strdup_printf("NICK %s", conn->nick);
	irc_send_cmd_now(server, cmd);
	g_free(cmd);

	/* send user/realname */
	address = server->connrec->address;
        ptr = strrchr(address, ':');
	if (ptr != NULL) {
		/* IPv6 address .. doesn't work here, use the string after
		   the last : char */
		address = ptr+1;
		if (*address == '\0')
			address = "x";
	}

	username = g_strdup(conn->username);
	ptr = strchr(username, ' ');
	if (ptr != NULL) *ptr = '\0';

	cmd = g_strdup_printf("USER %s %s %s :%s", username, username, address, conn->realname);
	irc_send_cmd_now(server, cmd);
	g_free(cmd);
	g_free(username);

	if (conn->proxy != NULL && conn->proxy_string_after != NULL) {
		cmd = g_strdup_printf(conn->proxy_string_after, conn->address, conn->port);
		irc_send_cmd_now(server, cmd);
		g_free(cmd);
	}

	server->isupport = g_hash_table_new((GHashFunc) g_istr_hash,
					    (GCompareFunc) g_istr_equal);

	/* set the standards */
	g_hash_table_insert(server->isupport, g_strdup("CHANMODES"), g_strdup("beIqd,k,lfJ,imnpst"));
	g_hash_table_insert(server->isupport, g_strdup("PREFIX"), g_strdup("(ohv)@%+"));

	server->cmdcount = 0;

	/* prevent the queue from sending too early, we have a max cut off of 120 secs */
	/* this will reset to 1 sec after we get the 001 event */
	g_get_current_time(&now);
	memcpy(&((IRC_SERVER_REC *)server)->wait_cmd, &now, sizeof(GTimeVal));
	((IRC_SERVER_REC *)server)->wait_cmd.tv_sec += 120;
}

SERVER_REC *irc_server_init_connect(SERVER_CONNECT_REC *conn)
{
	IRC_SERVER_CONNECT_REC *ircconn;
	IRC_SERVER_REC *server;

	g_return_val_if_fail(IS_IRC_SERVER_CONNECT(conn), NULL);
	if (conn->address == NULL || *conn->address == '\0') return NULL;
	if (conn->nick == NULL || *conn->nick == '\0') return NULL;

	server = g_new0(IRC_SERVER_REC, 1);
	server->chat_type = IRC_PROTOCOL;

	ircconn = (IRC_SERVER_CONNECT_REC *) conn;
	server->connrec = ircconn;
        server_connect_ref(conn);

	if (server->connrec->port <= 0) {
		server->connrec->port =
			server->connrec->use_ssl ? 6697 : 6667;
	}

	server->cmd_queue_speed = ircconn->cmd_queue_speed > 0 ?
		ircconn->cmd_queue_speed : settings_get_time("cmd_queue_speed");
	server->max_cmds_at_once = ircconn->max_cmds_at_once > 0 ?
		ircconn->max_cmds_at_once : settings_get_int("cmds_max_at_once");
	server->max_query_chans = ircconn->max_query_chans > 0 ?
		ircconn->max_query_chans : DEFAULT_MAX_QUERY_CHANS;

	server->max_kicks_in_cmd = ircconn->max_kicks > 0 ?
		ircconn->max_kicks : DEFAULT_MAX_KICKS;
	server->max_modes_in_cmd = ircconn->max_modes > 0 ?
		ircconn->max_modes : DEFAULT_MAX_MODES;
	server->max_whois_in_cmd = ircconn->max_whois > 0 ?
		ircconn->max_whois : DEFAULT_MAX_WHOIS;
	server->max_msgs_in_cmd = ircconn->max_msgs > 0 ?
		ircconn->max_msgs : DEFAULT_MAX_MSGS;
	server->connrec->use_ssl = conn->use_ssl;

	modes_server_init(server);

        server_connect_init((SERVER_REC *) server);
	return (SERVER_REC *) server;
}

void irc_server_connect(SERVER_REC *server)
{
	if (!server_start_connect(server)) {
                server_connect_unref(server->connrec);
		g_free(server);
	}
}

/* Returns TRUE if `command' is sent to `target' */
static int command_has_target(const char *cmd, const char *target)
{
	const char *p;
        int len;

        /* just assume the command is in form "<command> <target> <data>" */
        p = strchr(cmd, ' ');
	if (p == NULL) return FALSE;
	p++;

        len = strlen(target);
	return strncmp(p, target, len) == 0 && p[len] == ' ';
}

/* Purge server output, either all or for specified target */
void irc_server_purge_output(IRC_SERVER_REC *server, const char *target)
{
	GSList *tmp, *next, *link;
        REDIRECT_REC *redirect;
	char *cmd;

	if (target != NULL && *target == '\0')
                target = NULL;

	for (tmp = server->cmdqueue; tmp != NULL; tmp = next) {
		next = tmp->next->next;
		cmd = tmp->data;
                redirect = tmp->next->data;

		if ((target == NULL || command_has_target(cmd, target)) &&
		    g_ascii_strncasecmp(cmd, "PONG ", 5) != 0) {
                        /* remove the redirection */
                        link = tmp->next;
			server->cmdqueue =
				g_slist_remove_link(server->cmdqueue, link);
                        g_slist_free_1(link);

			if (redirect != NULL)
                                server_redirect_destroy(redirect);

                        /* remove the command */
			server->cmdqueue =
				g_slist_remove(server->cmdqueue, cmd);
                        g_free(cmd);
                        server->cmdcount--;
		}
	}
}

static void sig_connected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	server->isnickflag = isnickflag_func;
	server->ischannel = ischannel_func;
	server->send_message = send_message;
	server->query_find_func =
		(QUERY_REC *(*)(SERVER_REC *, const char *)) irc_query_find;
	server->nick_comp_func = irc_nickcmp_rfc1459;

	server->splits = g_hash_table_new((GHashFunc) g_istr_hash,
					  (GCompareFunc) g_istr_equal);

        if (!server->session_reconnect)
		server_init(server);
}

static void isupport_destroy_hash(void *key, void *value)
{
	g_free(key);
	g_free(value);
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (!IS_IRC_SERVER(server))
		return;

	for (tmp = server->cmdqueue; tmp != NULL; tmp = tmp->next->next) {
		g_free(tmp->data);
		if (tmp->next->data != NULL)
                        server_redirect_destroy(tmp->next->data);
	}
	g_slist_free(server->cmdqueue);
        server->cmdqueue = NULL;

	/* these are dynamically allocated only if isupport was sent */
	g_hash_table_foreach(server->isupport,
			     (GHFunc) isupport_destroy_hash, server);
	g_hash_table_destroy(server->isupport);
	server->isupport = NULL;

	g_free_and_null(server->wanted_usermode);
	g_free_and_null(server->real_address);
	g_free_and_null(server->usermode);
	g_free_and_null(server->userhost);
	g_free_and_null(server->last_invite);
}

static void sig_server_quit(IRC_SERVER_REC *server, const char *msg)
{
	char *str;
	char *recoded;

	if (!IS_IRC_SERVER(server) || !server->connected)
		return;

	recoded = recode_out(SERVER(server), msg, NULL);
	str = g_strdup_printf("QUIT :%s", recoded);
	irc_send_cmd_now(server, str);
	g_free(str);
	g_free(recoded);
}

void irc_server_send_action(IRC_SERVER_REC *server, const char *target, const char *data)
{
	char *recoded;

	recoded = recode_out(SERVER(server), data, target);
	irc_send_cmdv(server, "PRIVMSG %s :\001ACTION %s\001", target, recoded);
	g_free(recoded);
}

void irc_server_send_away(IRC_SERVER_REC *server, const char *reason)
{
	char *recoded = NULL;

	if (!IS_IRC_SERVER(server))
		return;

	if (*reason != '\0' || server->usermode_away) {
		g_free_and_null(server->away_reason);
                if (*reason != '\0') {
			server->away_reason = g_strdup(reason);
			reason = recoded = recode_out(SERVER(server), reason, NULL);
		}

		irc_send_cmdv(server, "AWAY :%s", reason);
	}
	g_free(recoded);
}

void irc_server_send_data(IRC_SERVER_REC *server, const char *data, int len)
{
	if (net_sendbuffer_send(server->handle, data, len) == -1) {
		/* something bad happened */
		server->connection_lost = TRUE;
		return;
	}

	g_get_current_time(&server->last_cmd);

	/* A bit kludgy way to do the flood protection. In ircnet, there
	   actually is 1sec / 100 bytes penalty, but we rather want to deal
	   with the max. 1000 bytes input buffer problem. If we send more
	   than that with the burst, we'll get excess flooded. */
	if (len < 100 || server->cmd_queue_speed <= 10)
		server->wait_cmd.tv_sec = 0;
	else {
		memcpy(&server->wait_cmd, &server->last_cmd, sizeof(GTimeVal));
		server->wait_cmd.tv_sec += 2 + len/100;
	}
}

static int server_cmd_timeout(IRC_SERVER_REC *server, GTimeVal *now)
{
	REDIRECT_REC *redirect;
        GSList *link;
	long usecs;
	char *cmd;
	int len;

	if (!IS_IRC_SERVER(server))
		return 0;

	if (server->cmdcount == 0 && server->cmdqueue == NULL)
		return 0;

	if (g_timeval_cmp(now, &server->wait_cmd) == -1)
		return 1;

	usecs = get_timeval_diff(now, &server->last_cmd);
	if (usecs < server->cmd_queue_speed)
		return 1;

	server->cmdcount--;
	if (server->cmdqueue == NULL) return 1;

        /* get command */
	cmd = server->cmdqueue->data;
        redirect = server->cmdqueue->next->data;

	/* send command */
	len = strlen(cmd);
	irc_server_send_data(server, cmd, len);

	/* add to rawlog without [CR+]LF */
        if (len > 2 && cmd[len-2] == '\r')
		cmd[len-2] = '\0';
        else if (cmd[len-1] == '\n')
		cmd[len-1] = '\0';
	rawlog_output(server->rawlog, cmd);
	server_redirect_command(server, cmd, redirect);

	/* remove from queue */
	server->cmdqueue = g_slist_remove(server->cmdqueue, cmd);
	g_free(cmd);

        link = server->cmdqueue;
	server->cmdqueue = g_slist_remove_link(server->cmdqueue, link);
        g_slist_free_1(link);
	return 1;
}

/* check every now and then if there's data to be sent in command buffer */
static int servers_cmd_timeout(void)
{
	GTimeVal now;
	GSList *tmp;
	int keep = 0;

	g_get_current_time(&now);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		keep |= server_cmd_timeout(tmp->data, &now);
	}
	if (keep)
		return 1;
	else {
		cmd_tag = -1;
		return 0;
	}
}

/* Start the timeout for sending data later and decreasing cmdcount again */
void irc_servers_start_cmd_timeout(void)
{
	if (cmd_tag == -1)
		cmd_tag = g_timeout_add(500, (GSourceFunc) servers_cmd_timeout, NULL);
}

/* Return a string of all channels (and keys, if any have them) in server,
   like "#a,#b,#c,#d x,b_chan_key,x,x" or just "#e,#f,#g" */
char *irc_server_get_channels(IRC_SERVER_REC *server)
{
	GSList *tmp;
	GString *chans, *keys;
	char *ret;
	int use_keys;

	g_return_val_if_fail(server != NULL, FALSE);

	chans = g_string_new(NULL);
	keys = g_string_new(NULL);
	use_keys = FALSE;

	/* get currently joined channels */
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		g_string_append_printf(chans, "%s,", channel->name);
		g_string_append_printf(keys, "%s,", channel->key == NULL ? "x" :
				  channel->key);
		if (channel->key != NULL)
			use_keys = TRUE;
	}

	/* get also the channels that are in rejoin list */
	for (tmp = server->rejoin_channels; tmp != NULL; tmp = tmp->next) {
		REJOIN_REC *rec = tmp->data;

		g_string_append_printf(chans, "%s,", rec->channel);
		g_string_append_printf(keys, "%s,", rec->key == NULL ? "x" :
				  rec->key);
		if (rec->key != NULL) use_keys = TRUE;
	}

	if (chans->len > 0) {
		g_string_truncate(chans, chans->len-1);
		g_string_truncate(keys, keys->len-1);
		if (use_keys) g_string_append_printf(chans, " %s", keys->str);
	}

	ret = chans->str;
	g_string_free(chans, FALSE);
	g_string_free(keys, TRUE);

	return ret;
}

static void event_connected(IRC_SERVER_REC *server, const char *data, const char *from)
{
	char *params, *nick;
	GTimeVal now;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 1, &nick);

	if (strcmp(server->nick, nick) != 0) {
		/* nick changed unexpectedly .. connected via proxy, etc. */
		g_free(server->nick);
		server->nick = g_strdup(nick);
	}

	/* set the server address */
	g_free(server->real_address);
	server->real_address = from == NULL ?
		g_strdup(server->connrec->address) : /* shouldn't happen.. */
		g_strdup(from);

	/* last welcome message found - commands can be sent to server now. */
	server->connected = 1;
	server->real_connect_time = time(NULL);

	/* let the queue send now that we are identified */
	g_get_current_time(&now);
	memcpy(&server->wait_cmd, &now, sizeof(GTimeVal));

	if (server->connrec->usermode != NULL) {
		/* Send the user mode, before the autosendcmd.
		 * Do not pass this through cmd_mode because it
		 * is not known whether the resulting MODE message
		 * (if any) is the initial umode or a reply to this.
		 */
		irc_send_cmdv(server, "MODE %s %s", server->nick,
				server->connrec->usermode);
		g_free_not_null(server->wanted_usermode);
		server->wanted_usermode = g_strdup(server->connrec->usermode);
	}

	signal_emit("event connected", 1, server);
	g_free(params);
}

static void event_server_info(IRC_SERVER_REC *server, const char *data)
{
	char *params, *ircd_version, *usermodes, *chanmodes;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 5, NULL, NULL, &ircd_version, &usermodes, &chanmodes);

	/* check if server understands I and e channel modes */
	if (strchr(chanmodes, 'I') && strchr(chanmodes, 'e'))
		server->emode_known = TRUE;

	/* save server version */
	g_free_not_null(server->version);
	server->version = g_strdup(ircd_version);

	g_free(params);
}

static void parse_chanmodes(IRC_SERVER_REC *server, const char *sptr)
{
	mode_func_t *modefuncs[] = {
		modes_type_a,
		modes_type_b,
		modes_type_c,
		modes_type_d
	};
	char **item, **chanmodes;
	int i;

	chanmodes = g_strsplit(sptr, ",", 5); /* ignore extras */

	for (i = 0, item = chanmodes; *item != NULL && i < 4; item++, i++) {
		unsigned char *p = (unsigned char*) *item;
		while (*p != '\0') {
			server->modes[(int)*p].func = modefuncs[i];
			p++;
		}
	}

	g_strfreev(chanmodes);
}

static void parse_prefix(IRC_SERVER_REC *server, const char *sptr)
{
	const char *eptr;

	if (*sptr++ != '(')
		return; /* Unknown prefix format */

	eptr = strchr(sptr, ')');
	if (eptr == NULL)
		return;

	eptr++;
	while (*sptr != '\0' && *eptr != '\0' && *sptr != ')' && *eptr != ' ') {
		server->modes[(int)(unsigned char) *sptr].func =
			modes_type_prefix;
		server->modes[(int)(unsigned char) *sptr].prefix = *eptr;
		server->prefix[(int)(unsigned char) *eptr] = *sptr;
		sptr++; eptr++;
	}
}


static void event_isupport(IRC_SERVER_REC *server, const char *data)
{
	char **item, *sptr, *eptr;
	char **isupport;
	gpointer key, value;
   
	g_return_if_fail(server != NULL);

	server->isupport_sent = TRUE;

	sptr = strchr(data, ' ');
	if (sptr == NULL)
		return;
	sptr++;

	isupport = g_strsplit(sptr, " ", -1);

	for(item = isupport; *item != NULL; item++) {
		int removed = FALSE;

		if (**item == '\0')
			continue;

		if (**item == ':')
			break;

		sptr = strchr(*item, '=');
		if (sptr != NULL) {
			*sptr = '\0';
			sptr++;
		}

		eptr = *item;
		if(*eptr == '-') {
			removed = TRUE;
			eptr++;
		}

		key = value = NULL;
		if (!g_hash_table_lookup_extended(server->isupport, eptr,
						  &key, &value) && removed)
			continue;

		g_hash_table_remove(server->isupport, eptr);
		if (!removed) {
			g_hash_table_insert(server->isupport, g_strdup(eptr),
					    g_strdup(sptr != NULL ? sptr : ""));
		}

		g_free(key);
		g_free(value);
	}
	g_strfreev(isupport);
	irc_server_init_isupport(server);

}

static void event_motd(IRC_SERVER_REC *server, const char *data, const char *from)
{
	if (server->connected)
		return;

	/* Stupid broken piece of shit ircd didn't send us 001,
	   you'd think they could at least get that right??
	   But no, then I'll have to go and add these idiotic kludges
	   to make them work. Maybe I should instead get the users of these
	   servers to complain about it to their admins.

	   Oh, and looks like it also doesn't answer anything to PINGs,
	   disable lag checking. */
        server->disable_lag = TRUE;
	event_connected(server, data, from);
}

static void event_end_of_motd(IRC_SERVER_REC *server, const char *data)
{
	server->motd_got = TRUE;
}

static void event_channels_formed(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channels;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &channels);
        server->channels_formed = atoi(channels);
	g_free(params);
}

static void event_hosthidden(IRC_SERVER_REC *server, const char *data)
{
	char *params, *newhost, *p, *newuserhost;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &newhost);
	/* do a sanity check */
	if (!strchr(newhost, '*') && !strchr(newhost, '?') &&
			!strchr(newhost, '!') && !strchr(newhost, '#') &&
			!strchr(newhost, '&') && !strchr(newhost, ' ') &&
			*newhost != '\0' && *newhost != '@' &&
			*newhost != ':' && *newhost != '-' &&
			newhost[strlen(newhost) - 1] != '-') {
		if (strchr(newhost, '@')) {
			newuserhost = g_strdup(newhost);
			g_free(server->userhost);
			server->userhost = newuserhost;
		} else if (server->userhost != NULL) {
			/* no user@, only process if we know the user@
			 * already
			 */
			p = strchr(server->userhost, '@');
			if (p == NULL)
				p = server->userhost;
			newuserhost = g_strdup_printf("%.*s@%s", (int)(p - server->userhost), server->userhost, newhost);
			g_free(server->userhost);
			server->userhost = newuserhost;
		}
	}
	g_free(params);
}

static void event_server_banned(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(server != NULL);

        server->banned = TRUE;
}

static void event_error(IRC_SERVER_REC *server, const char *data)
{
	g_return_if_fail(server != NULL);

	if (!server->connected && (stristr(data, "Unauthorized") != NULL ||
				   stristr(data, "K-lined") != NULL ||
				   stristr(data, "Banned") != NULL ||
				   stristr(data, "Bad user info") != NULL))
		server->banned = TRUE;
}

static void event_ping(IRC_SERVER_REC *server, const char *data)
{
	char *params, *origin, *target, *str;

	params = event_get_params(data, 2, &origin, &target);
	str = *target == '\0' ? g_strconcat("PONG :", origin, NULL) :
		g_strdup_printf("PONG %s :%s", target, origin);
	irc_send_cmd_now(server, str);
        g_free(str);
	g_free(params);
}

static void event_empty(void)
{
}

void irc_server_init_isupport(IRC_SERVER_REC *server)
{
	char *sptr;
	gpointer key, value;
	/* chanmodes/prefix will fully override defaults */
	memset(server->modes, 0, sizeof(server->modes));
	memset(server->prefix, 0, sizeof(server->prefix));

	if ((sptr = g_hash_table_lookup(server->isupport, "CHANMODES")))
		parse_chanmodes(server, sptr);

	/* This is after chanmode because some servers define modes in both */
	if (g_hash_table_lookup_extended(server->isupport, "PREFIX",
					 &key, &value)) {
		sptr = value;
		if (*sptr != '(') {
			/* server incompatible with isupport draft */
			g_hash_table_remove(server->isupport, key);
			g_free(key);
			g_free(value);
			sptr = NULL;
		}
	} else {
		sptr = NULL;
	}

	if (sptr == NULL) {
		sptr = g_strdup("(ohv)@%+");
		g_hash_table_insert(server->isupport, g_strdup("PREFIX"), sptr);
	}
	parse_prefix(server, sptr);

	if ((sptr = g_hash_table_lookup(server->isupport, "MODES"))) {
		server->max_modes_in_cmd = atoi(sptr);
		if (server->max_modes_in_cmd < 1)
			server->max_modes_in_cmd = DEFAULT_MAX_MODES;
	}

	if ((sptr = g_hash_table_lookup(server->isupport, "CASEMAPPING"))) {
		if (strstr(sptr, "rfc1459") != NULL)
			server->nick_comp_func = irc_nickcmp_rfc1459;
		else
			server->nick_comp_func = irc_nickcmp_ascii;
	}

	if ((sptr = g_hash_table_lookup(server->isupport, "TARGMAX"))) {
		char *p = sptr;
		server->max_kicks_in_cmd = 1;
		server->max_msgs_in_cmd = 1;
		/* Not doing WHOIS here until it is clear what it means. */
		while (*p != '\0') {
			if (!g_ascii_strncasecmp(p, "KICK:", 5)) {
				server->max_kicks_in_cmd = atoi(p + 5);
				if (server->max_kicks_in_cmd <= 0)
					server->max_kicks_in_cmd = 30;
			} else if (!g_ascii_strncasecmp(p, "PRIVMSG:", 8)) {
				server->max_msgs_in_cmd = atoi(p + 8);
				if (server->max_msgs_in_cmd <= 0)
					server->max_msgs_in_cmd = 30;
			}
			p = strchr(p, ',');
			if (p == NULL)
				break;
			p++;
		}
	} else if ((sptr = g_hash_table_lookup(server->isupport, "MAXTARGETS"))) {
		server->max_msgs_in_cmd = atoi(sptr);
		if (server->max_msgs_in_cmd <= 0)
			server->max_msgs_in_cmd = 1;
	}
}

void irc_servers_init(void)
{
	settings_add_str("misc", "usermode", DEFAULT_USER_MODE);
	settings_add_time("flood", "cmd_queue_speed", DEFAULT_CMD_QUEUE_SPEED);
	settings_add_int("flood", "cmds_max_at_once", DEFAULT_CMDS_MAX_AT_ONCE);

	cmd_tag = -1;

	signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
	signal_add_last("server disconnected", (SIGNAL_FUNC) sig_disconnected);
	signal_add_last("server quit", (SIGNAL_FUNC) sig_server_quit);
	signal_add("event 001", (SIGNAL_FUNC) event_connected);
	signal_add("event 004", (SIGNAL_FUNC) event_server_info);
	signal_add("event 005", (SIGNAL_FUNC) event_isupport);
	signal_add("event 375", (SIGNAL_FUNC) event_motd);
	signal_add_last("event 376", (SIGNAL_FUNC) event_end_of_motd);
	signal_add_last("event 422", (SIGNAL_FUNC) event_end_of_motd); /* no motd */
	signal_add("event 254", (SIGNAL_FUNC) event_channels_formed);
	signal_add("event 396", (SIGNAL_FUNC) event_hosthidden);
	signal_add("event 465", (SIGNAL_FUNC) event_server_banned);
	signal_add("event error", (SIGNAL_FUNC) event_error);
	signal_add("event ping", (SIGNAL_FUNC) event_ping);
	signal_add("event empty", (SIGNAL_FUNC) event_empty);

	irc_servers_setup_init();
	irc_servers_reconnect_init();
	servers_redirect_init();
	servers_idle_init();
}

void irc_servers_deinit(void)
{
	if (cmd_tag != -1)
		g_source_remove(cmd_tag);

	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
        signal_remove("server quit", (SIGNAL_FUNC) sig_server_quit);
	signal_remove("event 001", (SIGNAL_FUNC) event_connected);
	signal_remove("event 004", (SIGNAL_FUNC) event_server_info);
	signal_remove("event 005", (SIGNAL_FUNC) event_isupport);
	signal_remove("event 375", (SIGNAL_FUNC) event_motd);
	signal_remove("event 376", (SIGNAL_FUNC) event_end_of_motd);
	signal_remove("event 422", (SIGNAL_FUNC) event_end_of_motd); /* no motd */
	signal_remove("event 254", (SIGNAL_FUNC) event_channels_formed);
	signal_remove("event 396", (SIGNAL_FUNC) event_hosthidden);
	signal_remove("event 465", (SIGNAL_FUNC) event_server_banned);
	signal_remove("event error", (SIGNAL_FUNC) event_error);
	signal_remove("event ping", (SIGNAL_FUNC) event_ping);
	signal_remove("event empty", (SIGNAL_FUNC) event_empty);

	irc_servers_setup_deinit();
	irc_servers_reconnect_deinit();
	servers_redirect_deinit();
	servers_idle_deinit();
}
