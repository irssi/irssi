/*
 irc-commands.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "commands.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"
#include "common-setup.h"

#include "bans.h"
#include "channels.h"
#include "irc-server.h"
#include "irc.h"
#include "nicklist.h"
#include "server-redirect.h"
#include "server-setup.h"

typedef struct {
	CHANNEL_REC *channel;
	char *ban;
        int timeleft;
} KNOCKOUT_REC;

static GString *tmpstr;
static int knockout_tag;

static IRC_SERVER_REC *connect_server(const char *data)
{
	IRC_SERVER_CONNECT_REC *conn;
	IRC_SERVER_REC *server;
	char *params, *addr, *portstr, *password, *nick;
	int port;

	g_return_val_if_fail(data != NULL, NULL);

	params = cmd_get_params(data, 4, &addr, &portstr, &password, &nick);
	if (*addr == '\0') return NULL;

	if (strcmp(password, "-") == 0)
		*password = '\0';

	port = 6667;
	if (*portstr != '\0')
		sscanf(portstr, "%d", &port);

	/* connect to server */
        conn = irc_server_create_conn(addr, port, password, nick);
	server = irc_server_connect(conn);

	g_free(params);
	return server;
}

static void cmd_connect(const char *data)
{
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
	connect_server(data);
}

static void cmd_disconnect(const char *data, IRC_SERVER_REC *server)
{
	IRC_SERVER_REC *ircserver;
	char *params, *tag, *msg;

	g_return_if_fail(data != NULL);

	if (g_strncasecmp(data, "RECON-", 6) == 0)
		return; /* remove reconnection, handle in server-reconnect.c */

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &tag, &msg);

	if (*tag != '\0' && strcmp(tag, "*") != 0)
		server = (IRC_SERVER_REC *) server_find_tag(tag);
	if (server == NULL || !irc_server_check(server))
		cmd_param_error(CMDERR_NOT_CONNECTED);

	ircserver = (IRC_SERVER_REC *) server;
	if (ircserver->handle != -1 && ircserver->buffer != NULL) {
		/* flush transmit queue */
		g_slist_foreach(ircserver->cmdqueue, (GFunc) g_free, NULL);
		g_slist_free(ircserver->cmdqueue);
		ircserver->cmdqueue = NULL;
		ircserver->cmdcount = 0;

		/* then send quit message */
		if (*msg == '\0') msg = (char *) settings_get_str("default_quit_message");
		irc_send_cmdv(ircserver, "QUIT :%s", msg);
	}
	g_free(params);

	server_disconnect((SERVER_REC *) server);
}

static void cmd_server(const char *data, IRC_SERVER_REC *server)
{
	char *channels, *away_reason, *usermode, *ircnet;

	g_return_if_fail(data != NULL);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*data == '+' || server == NULL) {
		channels = away_reason = usermode = ircnet = NULL;
	} else {
		ircnet = g_strdup(server->connrec->ircnet);
		channels = irc_server_get_channels((IRC_SERVER_REC *) server);
		if (*channels == '\0')
			g_free_and_null(channels);
		usermode = g_strdup(server->usermode);
		away_reason = !server->usermode_away ? NULL :
			g_strdup(server->away_reason);
		cmd_disconnect("* Changing server", server);
	}

	server = connect_server(data + (*data == '+' ? 1 : 0));
	if (*data == '+' || server == NULL ||
	    (ircnet != NULL && server->connrec->ircnet != NULL &&
	     g_strcasecmp(ircnet, server->connrec->ircnet) != 0)) {
		g_free_not_null(channels);
		g_free_not_null(usermode);
		g_free_not_null(away_reason);
	} else if (server != NULL) {
		server->connrec->reconnection = TRUE;
		server->connrec->channels = channels;
		server->connrec->usermode = usermode;
		server->connrec->away_reason = away_reason;
	}
	g_free_not_null(ircnet);
}

static void cmd_quit(const char *data)
{
	GSList *tmp, *next;
	const char *quitmsg;
	char *str;

	g_return_if_fail(data != NULL);

	quitmsg = *data != '\0' ? data :
		settings_get_str("default_quit_message");

	/* disconnect from every server */
	for (tmp = servers; tmp != NULL; tmp = next) {
		next = tmp->next;

		str = g_strdup_printf("* %s", quitmsg);
		cmd_disconnect(str, tmp->data);
		g_free(str);
	}

	signal_emit("gui exit", 0);
}

static void cmd_msg(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *target, *msg;
	int free_ret;

	g_return_if_fail(data != NULL);

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*target == '=') {
		/* dcc msg - don't even try to handle here.. */
		g_free(params);
		return;
	}

	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_param_error(CMDERR_NOT_CONNECTED);

	free_ret = FALSE;
	if (strcmp(target, ",") == 0 || strcmp(target, ".") == 0)
		target = parse_special(&target, server, item, NULL, &free_ret, NULL);
	else if (strcmp(target, "*") == 0 &&
		 (irc_item_channel(item) || irc_item_query(item)))
		target = item->name;
	if (target != NULL) {
		g_string_sprintf(tmpstr, "PRIVMSG %s :%s", target, msg);
		irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);
	}

	if (free_ret && target != NULL) g_free(target);

	g_free(params);
}

static void cmd_notice(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *msg;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	g_string_sprintf(tmpstr, "NOTICE %s :%s", target, msg);
	irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);

	g_free(params);
}

static void cmd_ctcp(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *ctcpcmd, *ctcpdata;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata);
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	g_strup(ctcpcmd);
	if (*ctcpdata == '\0')
		g_string_sprintf(tmpstr, "PRIVMSG %s :\001%s\001", target, ctcpcmd);
	else
		g_string_sprintf(tmpstr, "PRIVMSG %s :\001%s %s\001", target, ctcpcmd, ctcpdata);
	irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);

	g_free(params);
}

static void cmd_nctcp(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *ctcpcmd, *ctcpdata;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &target, &ctcpcmd, &ctcpdata);
	if (*target == '\0' || *ctcpcmd == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	g_strup(ctcpcmd);
	g_string_sprintf(tmpstr, "NOTICE %s :\001%s %s\001", target, ctcpcmd, ctcpdata);
	irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);

	g_free(params);
}

static void cmd_join(const char *data, IRC_SERVER_REC *server)
{
	if (*data == '\0' || g_strncasecmp(data, "-invite", 7) == 0) {
		if (server->last_invite != NULL)
			channels_join(server, server->last_invite, FALSE);
	} else
		channels_join(server, data, FALSE);
}

static void cmd_part(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channame, *msg;
	CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST, item, &channame, &msg);
	if (*channame == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	irc_send_cmdv(server, *msg == '\0' ? "PART %s" : "PART %s %s",
		      channame, msg);

	g_free(params);
}

static void cmd_kick(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channame, *nicks, *reason;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST,
				item, &channame, &nicks, &reason);

	if (*channame == '\0' || *nicks == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	if (!ischannel(*channame)) cmd_param_error(CMDERR_NOT_JOINED);

	g_string_sprintf(tmpstr, "KICK %s %s :%s", channame, nicks, reason);
	irc_send_cmd_split(server, tmpstr->str, 3, server->max_kicks_in_cmd);

	g_free(params);
}

static void cmd_topic(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channame, *topic;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST, item, &channame, &topic);

	irc_send_cmdv(server, *topic == '\0' ? "TOPIC %s" : "TOPIC %s :%s",
			 channame, topic);

	g_free(params);
}

static void cmd_invite(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *nick, *channame;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2, &nick, &channame);
	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	if (*channame == '\0' || strcmp(channame, "*") == 0) {
		if (!irc_item_channel(item))
			cmd_param_error(CMDERR_NOT_JOINED);

		channame = item->name;
	}

	irc_send_cmdv(server, "INVITE %s %s", nick, channame);
	g_free(params);
}

static void cmd_list(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *args, *str;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTARGS | PARAM_FLAG_GETREST, &args, &str);

	if (*str == '\0' && stristr(args, "-yes") == NULL)
		cmd_param_error(CMDERR_NOT_GOOD_IDEA);

	irc_send_cmdv(server, "LIST %s", str);
	g_free(params);

	/* add default redirection */
	server_redirect_default((SERVER_REC *) server, "bogus command list");
}

static void cmd_who(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channel, *args, *rest;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 3 | PARAM_FLAG_OPTARGS | PARAM_FLAG_GETREST, &args, &channel, &rest);

	if (strcmp(channel, "*") == 0 || *channel == '\0') {
		if (!irc_item_check(item))
                        cmd_return_error(CMDERR_NOT_JOINED);

		data = item->name;
	}
	if (strcmp(channel, "**") == 0) {
		/* ** displays all nicks.. */
		*channel = '\0';
	}

	irc_send_cmdv(server, *rest == '\0' ? "WHO %s" : "WHO %s %s",
		      channel, rest);
	g_free(params);

	/* add default redirection */
	server_redirect_default((SERVER_REC *) server, "bogus command who");
}

static void cmd_names(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	g_return_if_fail(data != NULL);

	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_GOOD_IDEA);

	if (strcmp(data, "*") == 0) {
		if (!irc_item_channel(item))
			cmd_return_error(CMDERR_NOT_JOINED);

		data = item->name;
	}

	if (g_strcasecmp(data, "-YES") == 0)
		irc_send_cmd(server, "NAMES");
	else
		irc_send_cmdv(server, "NAMES %s", data);
}

static void cmd_whois(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	while (*data == ' ') data++;
	if (*data == '\0') data = server->nick;

	g_string_sprintf(tmpstr, "WHOIS %s", data);
	irc_send_cmd_split(server, tmpstr->str, 2, server->max_whois_in_cmd);
}

static void cmd_whowas(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	while (*data == ' ') data++;
	if (*data == '\0') data = server->nick;

	irc_send_cmdv(server, "WHOWAS %s", data);
}

static void cmd_ping(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	GTimeVal tv;
        char *str;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '\0' || strcmp(data, "*") == 0) {
		if (!irc_item_check(item))
                        cmd_return_error(CMDERR_NOT_JOINED);

		data = item->name;
	}

	g_get_current_time(&tv);

	str = g_strdup_printf("%s PING %ld %ld", data, tv.tv_sec, tv.tv_usec);
	signal_emit("command ctcp", 3, str, server, item);
	g_free(str);
}

static void server_send_away(IRC_SERVER_REC *server, const char *reason)
{
	g_free_not_null(server->away_reason);
	server->away_reason = g_strdup(reason);

	irc_send_cmdv(server, "AWAY :%s", reason);
}

static void cmd_away(const char *data, IRC_SERVER_REC *server)
{
	char *params, *args, *reason;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTARGS | PARAM_FLAG_GETREST, &args, &reason);

	if (stristr(args, "-all") != NULL)
		g_slist_foreach(servers, (GFunc) server_send_away, reason);
	else
		server_send_away(server, reason);

	g_free(params);
}

static void cmd_deop(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '\0')
		irc_send_cmdv(server, "MODE %s -o", server->nick);
}

static void cmd_sconnect(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	irc_send_cmdv(server, "CONNECT %s", data);
}

static void cmd_quote(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	irc_send_cmd(server, data);
}

static void cmd_wall_hash(gpointer key, NICK_REC *nick, GSList **nicks)
{
	if (nick->op) *nicks = g_slist_append(*nicks, nick);
}

static void cmd_wall(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channame, *msg;
	CHANNEL_REC *chanrec;
	GSList *tmp, *nicks;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST, item, &channame, &msg);
	if (*msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	/* send notice to all ops */
	nicks = NULL;
	g_hash_table_foreach(chanrec->nicks, (GHFunc) cmd_wall_hash, &nicks);

	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		irc_send_cmdv(server, "NOTICE %s :%s", rec->nick, msg);
	}
	g_slist_free(nicks);

	g_free(params);
}

static void cmd_cycle(gchar *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *channame, *msg;
	CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_OPTCHAN, item, &channame, &msg);
	if (*channame == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	irc_send_cmdv(server, *msg == '\0' ? "PART %s" : "PART %s %s",
		      channame, msg);
	irc_send_cmdv(server, chanrec->key == NULL ? "JOIN %s" : "JOIN %s %s",
		      channame, chanrec->key);

	g_free(params);
}

static void cmd_kickban(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = cmd_get_params(data, 1, &nick);
	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	signal_emit("command ban", 3, nick, server, item);
	signal_emit("command kick", 3, data, server, item);
	g_free(params);
}

static void knockout_destroy(IRC_SERVER_REC *server, KNOCKOUT_REC *rec)
{
	server->knockoutlist = g_slist_remove(server->knockoutlist, rec);
	g_free(rec->ban);
	g_free(rec);
}

/* timeout function: knockout */
static void knockout_timeout_server(IRC_SERVER_REC *server)
{
	GSList *tmp, *next;
	time_t t;

	g_return_if_fail(server != NULL);

	t = server->knockout_lastcheck == 0 ? 0 :
		time(NULL)-server->knockout_lastcheck;
	server->knockout_lastcheck = time(NULL);

	for (tmp = server->knockoutlist; tmp != NULL; tmp = next) {
		KNOCKOUT_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->timeleft > t)
			rec->timeleft -= t;
		else {
			/* timeout, unban. */
			ban_remove(rec->channel, rec->ban);
			knockout_destroy(server, rec);
		}
	}
}

static int knockout_timeout(void)
{
	g_slist_foreach(servers, (GFunc) knockout_timeout_server, NULL);
	return 1;
}

static void cmd_knockout(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	KNOCKOUT_REC *rec;
	CHANNEL_REC *channel;
	char *params, *nick, *reason, *timeoutstr, *str;
	int timeleft;

	g_return_if_fail(data != NULL);
	if (server == NULL) cmd_return_error(CMDERR_NOT_CONNECTED);

	channel = irc_item_channel(item);
	if (channel == NULL) cmd_return_error(CMDERR_NOT_JOINED);

	if (is_numeric(data, ' ')) {
		/* first argument is the timeout */
		params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &timeoutstr, &nick, &reason);
		timeleft = atol(timeoutstr);
	} else {
                timeleft = 0;
		params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &nick, &reason);
	}

	if (timeleft == 0) timeleft = settings_get_int("knockout_time");
	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	signal_emit("command ban", 3, nick, server, channel);

	str = g_strdup_printf("%s %s", nick, reason);
	signal_emit("command kick", 3, str, server, channel);
	g_free(str);

	/* create knockout record */
	rec = g_new(KNOCKOUT_REC, 1);
	rec->timeleft = timeleft;
	rec->channel = channel;
	rec->ban = ban_get_mask(channel, nick);

	server->knockoutlist = g_slist_append(server->knockoutlist, rec);

	g_free(params);
}

/* destroy all knockouts in server */
static void sig_server_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	while (server->knockoutlist != NULL)
		knockout_destroy(server, server->knockoutlist->data);
}

/* destroy all knockouts in channel */
static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	GSList *tmp, *next;

	g_return_if_fail(channel != NULL);
	if (channel->server == NULL) return;

	for (tmp = channel->server->knockoutlist; tmp != NULL; tmp = next) {
		KNOCKOUT_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->channel == channel)
			knockout_destroy(channel->server, rec);
	}
}

static void command_self(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	irc_send_cmdv(server, *data == '\0' ? "%s" : "%s %s", current_command, data);
}

static void command_1self(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	irc_send_cmdv(server, "%s :%s", current_command, data);
}

static void command_2self(const char *data, IRC_SERVER_REC *server)
{
	char *params, *target, *text;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
		cmd_return_error(CMDERR_NOT_CONNECTED);

	params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &text);
	if (*target == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	irc_send_cmdv(server, "%s %s :%s", current_command, target, text);
	g_free(params);
}

static void sig_connected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	server_redirect_init((SERVER_REC *) server, "", 2, "event 318", "event 402", "event 401",
			     "event 301", "event 311", "event 312", "event 313",
			     "event 317", "event 319", NULL);

	/* gui-gnome can use server_redirect_event() in who/list commands so
	   we can't use "command who" or list here.. */
	server_redirect_init((SERVER_REC *) server, "bogus command who", 2, "event 401", "event 315", "event 352", NULL);
	server_redirect_init((SERVER_REC *) server, "bogus command list", 1, "event 321", "event 322", "event 323", NULL);
}

void irc_commands_init(void)
{
	tmpstr = g_string_new(NULL);

	settings_add_str("misc", "default_quit_message", "leaving");
	settings_add_int("misc", "knockout_time", 300);

	knockout_tag = g_timeout_add(KNOCKOUT_TIMECHECK, (GSourceFunc) knockout_timeout, NULL);

	signal_add("server connected", (SIGNAL_FUNC) sig_connected);
	command_bind("server", NULL, (SIGNAL_FUNC) cmd_server);
	command_bind("connect", NULL, (SIGNAL_FUNC) cmd_connect);
	command_bind("disconnect", NULL, (SIGNAL_FUNC) cmd_disconnect);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_bind("notice", NULL, (SIGNAL_FUNC) cmd_notice);
	command_bind("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind("nctcp", NULL, (SIGNAL_FUNC) cmd_nctcp);
	command_bind("quit", NULL, (SIGNAL_FUNC) cmd_quit);
	command_bind("join", NULL, (SIGNAL_FUNC) cmd_join);
	command_bind("part", NULL, (SIGNAL_FUNC) cmd_part);
	command_bind("kick", NULL, (SIGNAL_FUNC) cmd_kick);
	command_bind("topic", NULL, (SIGNAL_FUNC) cmd_topic);
	command_bind("invite", NULL, (SIGNAL_FUNC) cmd_invite);
	command_bind("list", NULL, (SIGNAL_FUNC) cmd_list);
	command_bind("who", NULL, (SIGNAL_FUNC) cmd_who);
	command_bind("names", NULL, (SIGNAL_FUNC) cmd_names);
	command_bind("nick", NULL, (SIGNAL_FUNC) command_self);
	command_bind("note", NULL, (SIGNAL_FUNC) command_self);
	command_bind("whois", NULL, (SIGNAL_FUNC) cmd_whois);
	command_bind("whowas", NULL, (SIGNAL_FUNC) cmd_whowas);
	command_bind("ping", NULL, (SIGNAL_FUNC) cmd_ping);
	command_bind("kill", NULL, (SIGNAL_FUNC) command_2self);
	command_bind("away", NULL, (SIGNAL_FUNC) cmd_away);
	command_bind("ison", NULL, (SIGNAL_FUNC) command_1self);
	command_bind("admin", NULL, (SIGNAL_FUNC) command_self);
	command_bind("info", NULL, (SIGNAL_FUNC) command_self);
	command_bind("links", NULL, (SIGNAL_FUNC) command_self);
	command_bind("lusers", NULL, (SIGNAL_FUNC) command_self);
	command_bind("map", NULL, (SIGNAL_FUNC) command_self);
	command_bind("motd", NULL, (SIGNAL_FUNC) command_self);
	command_bind("stats", NULL, (SIGNAL_FUNC) command_self);
	command_bind("time", NULL, (SIGNAL_FUNC) command_self);
	command_bind("trace", NULL, (SIGNAL_FUNC) command_self);
	command_bind("version", NULL, (SIGNAL_FUNC) command_self);
	command_bind("servlist", NULL, (SIGNAL_FUNC) command_self);
	command_bind("silence", NULL, (SIGNAL_FUNC) command_self);
	command_bind("sconnect", NULL, (SIGNAL_FUNC) cmd_sconnect);
	command_bind("squery", NULL, (SIGNAL_FUNC) command_2self);
	command_bind("deop", NULL, (SIGNAL_FUNC) cmd_deop);
	command_bind("die", NULL, (SIGNAL_FUNC) command_self);
	command_bind("hash", NULL, (SIGNAL_FUNC) command_self);
	command_bind("oper", NULL, (SIGNAL_FUNC) command_self);
	command_bind("restart", NULL, (SIGNAL_FUNC) command_self);
	command_bind("rping", NULL, (SIGNAL_FUNC) command_self);
	command_bind("squit", NULL, (SIGNAL_FUNC) command_2self);
	command_bind("uping", NULL, (SIGNAL_FUNC) command_self);
	command_bind("quote", NULL, (SIGNAL_FUNC) cmd_quote);
	command_bind("wall", NULL, (SIGNAL_FUNC) cmd_wall);
	command_bind("wallops", NULL, (SIGNAL_FUNC) command_1self);
	command_bind("wallchops", NULL, (SIGNAL_FUNC) command_2self);
	command_bind("cycle", NULL, (SIGNAL_FUNC) cmd_cycle);
	command_bind("kickban", NULL, (SIGNAL_FUNC) cmd_kickban);
	command_bind("knockout", NULL, (SIGNAL_FUNC) cmd_knockout);

	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
}

void irc_commands_deinit(void)
{
	g_source_remove(knockout_tag);

	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
	command_unbind("server", (SIGNAL_FUNC) cmd_server);
	command_unbind("connect", (SIGNAL_FUNC) cmd_connect);
	command_unbind("disconnect", (SIGNAL_FUNC) cmd_disconnect);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
	command_unbind("notice", (SIGNAL_FUNC) cmd_notice);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	command_unbind("nctcp", (SIGNAL_FUNC) cmd_nctcp);
	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);
	command_unbind("join", (SIGNAL_FUNC) cmd_join);
	command_unbind("part", (SIGNAL_FUNC) cmd_part);
	command_unbind("kick", (SIGNAL_FUNC) cmd_kick);
	command_unbind("topic", (SIGNAL_FUNC) cmd_topic);
	command_unbind("invite", (SIGNAL_FUNC) cmd_invite);
	command_unbind("list", (SIGNAL_FUNC) cmd_list);
	command_unbind("who", (SIGNAL_FUNC) cmd_who);
	command_unbind("names", (SIGNAL_FUNC) cmd_names);
	command_unbind("nick", (SIGNAL_FUNC) command_self);
	command_unbind("note", (SIGNAL_FUNC) command_self);
	command_unbind("whois", (SIGNAL_FUNC) cmd_whois);
	command_unbind("whowas", (SIGNAL_FUNC) cmd_whowas);
	command_unbind("ping", (SIGNAL_FUNC) cmd_ping);
	command_unbind("kill", (SIGNAL_FUNC) command_2self);
	command_unbind("away", (SIGNAL_FUNC) cmd_away);
	command_unbind("ison", (SIGNAL_FUNC) command_1self);
	command_unbind("admin", (SIGNAL_FUNC) command_self);
	command_unbind("info", (SIGNAL_FUNC) command_self);
	command_unbind("links", (SIGNAL_FUNC) command_self);
	command_unbind("lusers", (SIGNAL_FUNC) command_self);
	command_unbind("map", (SIGNAL_FUNC) command_self);
	command_unbind("motd", (SIGNAL_FUNC) command_self);
	command_unbind("stats", (SIGNAL_FUNC) command_self);
	command_unbind("time", (SIGNAL_FUNC) command_self);
	command_unbind("trace", (SIGNAL_FUNC) command_self);
	command_unbind("version", (SIGNAL_FUNC) command_self);
	command_unbind("servlist", (SIGNAL_FUNC) command_self);
	command_unbind("silence", (SIGNAL_FUNC) command_self);
	command_unbind("sconnect", (SIGNAL_FUNC) cmd_sconnect);
	command_unbind("squery", (SIGNAL_FUNC) command_2self);
	command_unbind("deop", (SIGNAL_FUNC) cmd_deop);
	command_unbind("die", (SIGNAL_FUNC) command_self);
	command_unbind("hash", (SIGNAL_FUNC) command_self);
	command_unbind("oper", (SIGNAL_FUNC) command_self);
	command_unbind("restart", (SIGNAL_FUNC) command_self);
	command_unbind("rping", (SIGNAL_FUNC) command_self);
	command_unbind("squit", (SIGNAL_FUNC) command_2self);
	command_unbind("uping", (SIGNAL_FUNC) command_self);
	command_unbind("quote", (SIGNAL_FUNC) cmd_quote);
	command_unbind("wall", (SIGNAL_FUNC) cmd_wall);
	command_unbind("wallops", (SIGNAL_FUNC) command_1self);
	command_unbind("wallchops", (SIGNAL_FUNC) command_2self);
	command_unbind("cycle", (SIGNAL_FUNC) cmd_cycle);
	command_unbind("kickban", (SIGNAL_FUNC) cmd_kickban);
	command_unbind("knockout", (SIGNAL_FUNC) cmd_knockout);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);

	g_string_free(tmpstr, TRUE);
}
