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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "misc.h"
#include "recode.h"
#include "special-vars.h"
#include "settings.h"
#include "window-item-def.h"

#include "servers-reconnect.h"
#include "servers-redirect.h"
#include "servers-setup.h"
#include "nicklist.h"

#include "bans.h"
#include "irc-commands.h"
#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-queries.h"

/* How often to check if there's anyone to be unbanned in knockout list */
#define KNOCKOUT_TIMECHECK 10000

/* /LIST: Max. number of channels in IRC network before -yes option
   is required */
#define LIST_MAX_CHANNELS_PASS 1000

/* When /PARTing a channel, if there's more messages in output queue
   than this, purge the output for channel. The idea behind this is that
   if you accidentally pasted some large text and /PART the channel, the
   text won't be fully pasted. Note that this counter is the whole size
   of the output queue, not channel specific.. */
#define MAX_COMMANDS_ON_PART_UNTIL_PURGE 10

typedef struct {
	IRC_CHANNEL_REC *channel;
	char *ban;
	time_t unban_time;
} KNOCKOUT_REC;

static GString *tmpstr;
static int knockout_tag;

/* SYNTAX: NOTICE <targets> <message> */
static void cmd_notice(const char *data, IRC_SERVER_REC *server,
		       WI_ITEM_REC *item)
{
	const char *target, *msg;
	char *recoded;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &target, &msg))
		return;
	if (strcmp(target, "*") == 0)
		target = item == NULL ? NULL : window_item_get_target(item);
	if (*target == '\0' || *msg == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	recoded = recode_out(SERVER(server), msg, target);
	g_string_printf(tmpstr, "NOTICE %s :%s", target, recoded);
	g_free(recoded);

	irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);

	cmd_params_free(free_arg);
}

/* SYNTAX: CTCP <targets> <ctcp command> [<ctcp data>] */
static void cmd_ctcp(const char *data, IRC_SERVER_REC *server,
		     WI_ITEM_REC *item)
{
	const char *target;
	char *ctcpcmd, *ctcpdata;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			    &target, &ctcpcmd, &ctcpdata))
		return;
	if (strcmp(target, "*") == 0)
		target = item == NULL ? NULL : window_item_get_target(item);
	if (*target == '\0' || *ctcpcmd == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	ascii_strup(ctcpcmd);
	if (*ctcpdata == '\0')
		g_string_printf(tmpstr, "PRIVMSG %s :\001%s\001", target, ctcpcmd);
	else {
		char *recoded;

		recoded = recode_out(SERVER(server), ctcpdata, target);
		g_string_printf(tmpstr, "PRIVMSG %s :\001%s %s\001", target, ctcpcmd, recoded);
		g_free(recoded);
	}

	irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);

	cmd_params_free(free_arg);
}

/* SYNTAX: NCTCP <targets> <ctcp command> [<ctcp data>] */
static void cmd_nctcp(const char *data, IRC_SERVER_REC *server,
		      WI_ITEM_REC *item)
{
	const char *target;
	char *ctcpcmd, *ctcpdata, *recoded;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			    &target, &ctcpcmd, &ctcpdata))
		return;
	if (strcmp(target, "*") == 0)
		target = item == NULL ? NULL : window_item_get_target(item);
	if (*target == '\0' || *ctcpcmd == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	ascii_strup(ctcpcmd);
	recoded = recode_out(SERVER(server), ctcpdata, target);
	g_string_printf(tmpstr, "NOTICE %s :\001%s %s\001", target, ctcpcmd, recoded);
	g_free(recoded);

	irc_send_cmd_split(server, tmpstr->str, 2, server->max_msgs_in_cmd);

	cmd_params_free(free_arg);
}

/* SYNTAX: PART [<channels>] [<message>] */
static void cmd_part(const char *data, IRC_SERVER_REC *server,
		     WI_ITEM_REC *item)
{
	char *channame, *msg;
	char *recoded = NULL;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST |
			    PARAM_FLAG_OPTCHAN, item, &channame, &msg))
		return;
	if (*channame == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*msg == '\0') msg = (char *) settings_get_str("part_message");

        if (server->cmdcount > MAX_COMMANDS_ON_PART_UNTIL_PURGE)
		irc_server_purge_output(server, channame);

	if (*msg != '\0')
		recoded = recode_out(SERVER(server), msg, channame);
	irc_send_cmdv(server, ! recoded ? "PART %s" : "PART %s :%s",
		      channame, recoded);

	g_free(recoded);
	cmd_params_free(free_arg);
}

/* SYNTAX: KICK [<channel>] <nicks> [<reason>] */
static void cmd_kick(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	char *channame, *nicks, *reason, *recoded;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST |
			    PARAM_FLAG_OPTCHAN, item,
			    &channame, &nicks, &reason))
		return;

	if (*channame == '\0' || *nicks == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	if (!ischannel(*channame)) cmd_param_error(CMDERR_NOT_JOINED);

	recoded = recode_out(SERVER(server), reason, channame);
	g_string_printf(tmpstr, "KICK %s %s :%s", channame, nicks, recoded);
	g_free(recoded);

	irc_send_cmd_split(server, tmpstr->str, 3, server->max_kicks_in_cmd);

	cmd_params_free(free_arg);
}

/* SYNTAX: TOPIC [-delete] [<channel>] [<topic>] */
static void cmd_topic(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	GHashTable *optlist;
	char *channame, *topic;
	char *recoded = NULL;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN |
			    PARAM_FLAG_OPTIONS | PARAM_FLAG_GETREST,
			    item, "topic", &optlist, &channame, &topic))
		return;

	if (*topic != '\0' || g_hash_table_lookup(optlist, "delete") != NULL)
		recoded = recode_out(SERVER(server), topic, channame);
	irc_send_cmdv(server, recoded == NULL ? "TOPIC %s" : "TOPIC %s :%s",
		      channame, recoded);
	g_free(recoded);

	cmd_params_free(free_arg);
}

/* SYNTAX: INVITE <nick> [<channel>] */
static void cmd_invite(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	char *nick, *channame;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2, &nick, &channame))
		return;

	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	if (*channame == '\0' || strcmp(channame, "*") == 0) {
		if (!IS_IRC_CHANNEL(item))
			cmd_param_error(CMDERR_NOT_JOINED);

		channame = IRC_CHANNEL(item)->name;
	}

	irc_send_cmdv(server, "INVITE %s %s", nick, channame);
	cmd_params_free(free_arg);
}

/* SYNTAX: LIST [-yes] [<channel>] */
static void cmd_list(const char *data, IRC_SERVER_REC *server,
		     WI_ITEM_REC *item)
{
	GHashTable *optlist;
	char *str;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST, "list", &optlist, &str))
		return;

	if (*str == '\0' && g_hash_table_lookup(optlist, "yes") == NULL &&
	    (server->channels_formed <= 0 ||
	     server->channels_formed > LIST_MAX_CHANNELS_PASS))
		cmd_param_error(CMDERR_NOT_GOOD_IDEA);

	irc_send_cmdv(server, "LIST %s", str);
	cmd_params_free(free_arg);
}

/* SYNTAX: WHO [<nicks> | <channels> | **] */
static void cmd_who(const char *data, IRC_SERVER_REC *server,
		    WI_ITEM_REC *item)
{
	char *channel, *rest;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &channel, &rest))
		return;

	if (strcmp(channel, "*") == 0 || *channel == '\0') {
		if (!IS_IRC_CHANNEL(item))
                        cmd_param_error(CMDERR_NOT_JOINED);

		channel = IRC_CHANNEL(item)->name;
	}
	if (strcmp(channel, "**") == 0) {
		/* ** displays all nicks.. */
		*channel = '\0';
	}

	irc_send_cmdv(server, *rest == '\0' ? "WHO %s" : "WHO %s %s",
		      channel, rest);
	cmd_params_free(free_arg);
}

static void cmd_names(const char *data, IRC_SERVER_REC *server,
		      WI_ITEM_REC *item)
{
        GHashTable *optlist;
	char *channel;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST, "names", &optlist, &channel))
		return;

	if (strcmp(channel, "*") == 0 || *channel == '\0') {
		if (!IS_IRC_CHANNEL(item))
                        cmd_param_error(CMDERR_NOT_JOINED);

		channel = IRC_CHANNEL(item)->name;
	}

	if (strcmp(channel, "**") == 0) {
		/* ** displays all nicks.. */
                irc_send_cmd(server, "NAMES");
	} else {
		irc_send_cmdv(server, "NAMES %s", channel);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: NICK <new nick> */
static void cmd_nick(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
        char *nick;
	void *free_arg;

	g_return_if_fail(data != NULL);

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1, &nick))
		return;

	g_free(server->last_nick);
	server->last_nick = g_strdup(nick);

	irc_send_cmdv(server, "NICK %s", nick);
	cmd_params_free(free_arg);
}

static char *get_redirect_nicklist(const char *nicks, int *free)
{
	char *str, *ret;

	if (*nicks != '!' && strchr(nicks, ',') == NULL) {
		*free = FALSE;
		return (char *) nicks;
	}

	*free = TRUE;

	/* ratbox-style operspy whois takes !nick, echoes that
	 * in RPL_ENDOFWHOIS as normal but gives output about the
	 * plain nick
	 */
	str = g_strdup(*nicks == '!' ? nicks + 1 : nicks);
	g_strdelimit(str, ",", ' ');
	ret = g_strconcat(str, " ", nicks, NULL);
	g_free(str);

	return ret;
}

/* SYNTAX: WHOIS [-<server tag>] [<server>] [<nicks>] */
static void cmd_whois(const char *data, IRC_SERVER_REC *server,
		      WI_ITEM_REC *item)
{
	GHashTable *optlist;
	char *qserver, *query, *event_402, *str;
	void *free_arg;
	int free_nick;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS,
			    "whois", &optlist, &qserver, &query))
		return;

	/* -<server tag> */
	server = IRC_SERVER(cmd_options_get_server("whois", optlist,
						   SERVER(server)));
	if (server == NULL) {
		cmd_params_free(free_arg);
		return;
	}

	if (*query == '\0') {
		query = qserver;
		qserver = "";
	}
	if (*query == '\0') {
		QUERY_REC *queryitem = QUERY(item);
		if (queryitem == NULL)
			query = server->nick;
		else
			query = qserver = queryitem->name;
	}

	if (strcmp(query, "*") == 0 &&
	    g_hash_table_lookup(optlist, "yes") == NULL)
		cmd_param_error(CMDERR_NOT_GOOD_IDEA);

	event_402 = "event 402";
	if (*qserver == '\0')
		g_string_printf(tmpstr, "WHOIS %s", query);
	else {
		g_string_printf(tmpstr, "WHOIS %s %s", qserver, query);
		if (g_strcasecmp(qserver, query) == 0)
			event_402 = "whois event not found";
	}

	query = get_redirect_nicklist(query, &free_nick);

	str = g_strconcat(qserver, " ", query, NULL);
	server_redirect_event(server, "whois", 1, str, TRUE,
		      NULL,
		      "event 318", "whois end",
		      "event 402", event_402,
		      "event 301", "whois away", /* 301 can come as a reply to /MSG, /WHOIS or /WHOWAS */
		      "event 313", "whois oper",
		      "event 401", (settings_get_bool("auto_whowas") ? "whois try whowas" : "whois event not found"),
		      "event 311", "whois event",
		      "", "whois default event", NULL);
        g_free(str);

	server->whois_found = FALSE;
	irc_send_cmd_split(server, tmpstr->str, 2, server->max_whois_in_cmd);

	if (free_nick) g_free(query);
	cmd_params_free(free_arg);
}

static void event_whois(IRC_SERVER_REC *server, const char *data,
			const char *nick, const char *addr)
{
	server->whois_found = TRUE;
	signal_emit("event 311", 4, server, data, nick, addr);
}

static void sig_whois_try_whowas(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);

	server->whowas_found = FALSE;
	server_redirect_event(server, "whowas", 1, nick, -1, NULL,
			      "event 314", "whowas event",
			      "event 369", "whowas event end",
			      "event 406", "event empty", NULL);
	irc_send_cmdv(server, "WHOWAS %s 1", nick);

	g_free(params);
}

static void event_end_of_whois(IRC_SERVER_REC *server, const char *data,
			       const char *nick, const char *addr)
{
	signal_emit("event 318", 4, server, data, nick, addr);
	server->whois_found = FALSE;
}

static void event_whowas(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *addr)
{
	server->whowas_found = TRUE;
	signal_emit("event 314", 4, server, data, nick, addr);
}

/* SYNTAX: WHOWAS [<nicks> [<count> [server]]] */
static void cmd_whowas(const char *data, IRC_SERVER_REC *server)
{
	char *nicks, *rest, *nicks_redir;
	void *free_arg;
	int free_nick;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &nicks, &rest))
		return;
	if (*nicks == '\0') nicks = server->nick;

	nicks_redir = get_redirect_nicklist(nicks, &free_nick);
	server_redirect_event(server, "whowas", 1, nicks_redir, -1, NULL,
			      "event 301", "whowas away", /* 301 can come as a reply to /MSG, /WHOIS or /WHOWAS */
			      "event 314", "whowas event", NULL);
	if (free_nick) g_free(nicks_redir);

	server->whowas_found = FALSE;
	irc_send_cmdv(server, *rest == '\0' ? "WHOWAS %s" :
		      "WHOWAS %s %s", nicks, rest);

	cmd_params_free(free_arg);
}

/* SYNTAX: PING [<nick> | <channel> | *] */
static void cmd_ping(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	GTimeVal tv;
        char *str;

        CMD_IRC_SERVER(server);

	if (*data == '\0') {
		if (!IS_QUERY(item))
			cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
		data = window_item_get_target(item);
	}

	g_get_current_time(&tv);

	str = g_strdup_printf("%s PING %ld %ld", data, tv.tv_sec, tv.tv_usec);
	signal_emit("command ctcp", 3, str, server, item);
	g_free(str);
}

/* SYNTAX: AWAY [-one | -all] [<reason>] */
static void cmd_away(const char *data, IRC_SERVER_REC *server)
{
	GHashTable *optlist;
	char *reason;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST, "away", &optlist, &reason)) return;

	if (g_hash_table_lookup(optlist, "one") != NULL)
		irc_server_send_away(server, reason);
	else
		g_slist_foreach(servers, (GFunc) irc_server_send_away, reason);

	cmd_params_free(free_arg);
}

/* SYNTAX: SCONNECT <new server> [[<port>] <existing server>] */
static void cmd_sconnect(const char *data, IRC_SERVER_REC *server)
{
        CMD_IRC_SERVER(server);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	irc_send_cmdv(server, "CONNECT %s", data);
}

/* SYNTAX: QUOTE <data> */
static void cmd_quote(const char *data, IRC_SERVER_REC *server)
{
	if (server != NULL && !IS_IRC_SERVER(server))
		return;
	if (server == NULL || server->connect_time == 0)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!server->connected)
		irc_send_cmd_now(server, data);
	else
		irc_send_cmd(server, data);
}

static void cmd_wall_hash(gpointer key, NICK_REC *nick, GSList **nicks)
{
	if (nick->op) *nicks = g_slist_append(*nicks, nick);
}

/* SYNTAX: WAIT [-<server tag>] <milliseconds> */
static void cmd_wait(const char *data, IRC_SERVER_REC *server)
{
	GHashTable *optlist;
	char *msecs;
	void *free_arg;
	int n;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    NULL, &optlist, &msecs))
		return;

	if (*msecs == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	/* -<server tag> */
	server = IRC_SERVER(cmd_options_get_server(NULL, optlist,
						   SERVER(server)));

	n = atoi(msecs);
	if (server != NULL && n > 0) {
		g_get_current_time(&server->wait_cmd);
		server->wait_cmd.tv_sec += n/1000;
		server->wait_cmd.tv_usec += n%1000;
		if (server->wait_cmd.tv_usec >= 1000) {
			server->wait_cmd.tv_sec++;
			server->wait_cmd.tv_usec -= 1000;
		}
	}
	cmd_params_free(free_arg);
}

/* SYNTAX: WALL [<channel>] <message> */
static void cmd_wall(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
	char *channame, *msg, *args, *recoded;
	void *free_arg;
	IRC_CHANNEL_REC *chanrec;
	GSList *tmp, *nicks;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN |
			    PARAM_FLAG_GETREST, item, &channame, &msg))
		return;
	if (*msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = irc_channel_find(server, channame);
	if (chanrec == NULL) cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	recoded = recode_out(SERVER(server), msg, channame);
	/* See if the server has advertised support of wallchops */
	if (g_hash_table_lookup(chanrec->server->isupport, "statusmsg") ||
	    g_hash_table_lookup(chanrec->server->isupport, "wallchops"))
		irc_send_cmdv(server, "NOTICE @%s :%s", chanrec->name, recoded);
	else {
		/* Fall back to manually noticing each op */
		nicks = NULL;
		g_hash_table_foreach(chanrec->nicks,
				     (GHFunc) cmd_wall_hash, &nicks);

		args = g_strconcat(chanrec->name, " ", recoded, NULL);
		msg = parse_special_string(settings_get_str("wall_format"),
					   SERVER(server), item, args, NULL, 0);
		g_free(args);

		for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
			NICK_REC *rec = tmp->data;

			if (rec != chanrec->ownnick) {
				irc_send_cmdv(server, "NOTICE %s :%s",
					      rec->nick, msg);
			}
		}

		g_free(msg);
		g_slist_free(nicks);
	}

	g_free(recoded);
	cmd_params_free(free_arg);
}

/* SYNTAX: KICKBAN [<channel>] <nicks> <reason> */
static void cmd_kickban(const char *data, IRC_SERVER_REC *server,
			WI_ITEM_REC *item)
{
        IRC_CHANNEL_REC *chanrec;
	char *channel, *nicks, *reason, *kickcmd, *bancmd, *recoded;
        char **nicklist, *spacenicks;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST,
			    item, &channel, &nicks, &reason))
		return;

	if (*channel == '\0' || *nicks == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL)
		cmd_param_error(CMDERR_CHAN_NOT_FOUND);

	nicklist = g_strsplit(nicks, ",", -1);
        spacenicks = g_strjoinv(" ", nicklist);
	g_strfreev(nicklist);

	recoded = recode_out(SERVER(server), reason, channel);
	kickcmd = g_strdup_printf("%s %s %s", chanrec->name, nicks, recoded);
	g_free(recoded);

	bancmd = g_strdup_printf("%s %s", chanrec->name, spacenicks);
        g_free(spacenicks);

        if (settings_get_bool("kick_first_on_kickban")) {
		signal_emit("command kick", 3, kickcmd, server, chanrec);
		signal_emit("command ban", 3, bancmd, server, chanrec);
	} else {
		signal_emit("command ban", 3, bancmd, server, chanrec);
		signal_emit("command kick", 3, kickcmd, server, chanrec);
	}
	g_free(kickcmd);
	g_free(bancmd);

	cmd_params_free(free_arg);
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
	time_t now;

	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

        now = time(NULL);
	for (tmp = server->knockoutlist; tmp != NULL; tmp = next) {
		KNOCKOUT_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->unban_time <= now) {
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

/* SYNTAX: KNOCKOUT [<time>] <nicks> <reason> */
static void cmd_knockout(const char *data, IRC_SERVER_REC *server,
			 IRC_CHANNEL_REC *channel)
{
	KNOCKOUT_REC *rec;
	char *nicks, *reason, *timeoutstr, *kickcmd, *bancmd, *recoded;
        char **nicklist, *spacenicks, *banmasks;
	void *free_arg;
	int timeleft;
	GSList *ptr;

        CMD_IRC_SERVER(server);

	if (!IS_IRC_CHANNEL(channel))
		cmd_return_error(CMDERR_NOT_JOINED);

	if (i_isdigit(*data)) {
		/* first argument is the timeout */
		if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
				    &timeoutstr, &nicks, &reason))
                        return;

		if (!parse_time_interval(timeoutstr, &timeleft))
			cmd_param_error(CMDERR_INVALID_TIME);
	} else {
		if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
				    &nicks, &reason))
			return;
                timeleft = settings_get_time("knockout_time");
	}

	if (*nicks == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	nicklist = g_strsplit(nicks, ",", -1);
        spacenicks = g_strjoinv(" ", nicklist);
	g_strfreev(nicklist);

	banmasks = ban_get_masks(channel, spacenicks, 0);
	g_free(spacenicks);

	recoded = recode_out(SERVER(server), reason, channel->name);
	kickcmd = g_strdup_printf("%s %s %s", channel->name, nicks, recoded);
	g_free(recoded);

	bancmd = *banmasks == '\0'? NULL :
		g_strdup_printf("%s %s", channel->name, banmasks);
	
        if (settings_get_bool("kick_first_on_kickban")) {
		signal_emit("command kick", 3, kickcmd, server, channel);
		if (bancmd != NULL)
			signal_emit("command ban", 3, bancmd, server, channel);
	} else {
		if (bancmd != NULL)
			signal_emit("command ban", 3, bancmd, server, channel);
		signal_emit("command kick", 3, kickcmd, server, channel);
	}
	g_free(kickcmd);
	g_free_not_null(bancmd);

	if (*banmasks == '\0')
		g_free(banmasks);
	else {
		/* check if we already have this knockout */
		for (ptr = server->knockoutlist; ptr != NULL; ptr = ptr->next) {
			rec = ptr->data;
			if (channel == rec->channel &&
					!strcmp(rec->ban, banmasks))
				break;
		}
		if (ptr == NULL) {
			rec = g_new(KNOCKOUT_REC, 1);
			rec->channel = channel;
			rec->ban = banmasks;
			server->knockoutlist = g_slist_append(server->knockoutlist, rec);
		}
		rec->unban_time = time(NULL)+timeleft/1000;
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: SERVER PURGE [<target>] */
static void cmd_server_purge(const char *data, IRC_SERVER_REC *server)
{
        char *target;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 1, &target))
		return;

	irc_server_purge_output(server, *target == '\0' ? NULL : target);

	cmd_params_free(free_arg);
}

/* destroy all knockouts in server */
static void sig_server_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	g_free(server->last_nick);

	while (server->knockoutlist != NULL)
		knockout_destroy(server, server->knockoutlist->data);
}

/* destroy all knockouts in channel */
static void sig_channel_destroyed(IRC_CHANNEL_REC *channel)
{
	GSList *tmp, *next;

	if (!IS_IRC_CHANNEL(channel) || !IS_IRC_SERVER(channel->server))
		return;

	for (tmp = channel->server->knockoutlist; tmp != NULL; tmp = next) {
		KNOCKOUT_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->channel == channel)
			knockout_destroy(channel->server, rec);
	}
}

/* SYNTAX: OPER [<nick> [<password>]] */
static void cmd_oper(const char *data, IRC_SERVER_REC *server)
{
	char *nick, *password;
	void *free_arg;

        CMD_IRC_SERVER(server);

        /* asking for password is handled by fe-common */
	if (!cmd_get_params(data, &free_arg, 2, &nick, &password))
		return;
        if (*password == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	irc_send_cmdv(server, "OPER %s %s", nick, password);
	cmd_params_free(free_arg);
}

/* SYNTAX: ACCEPT [[-]nick,...] */
static void cmd_accept(const char *data, IRC_SERVER_REC *server)
{
        CMD_IRC_SERVER(server);

	if (*data == '\0') 
		irc_send_cmd(server, "ACCEPT *");
	else
		irc_send_cmdv(server, "ACCEPT %s", data);
}

/* SYNTAX: UNSILENCE <nick!user@host> */
static void cmd_unsilence(const char *data, IRC_SERVER_REC *server)
{
        CMD_IRC_SERVER(server);

	if (*data == '\0') 
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	irc_send_cmdv(server, "SILENCE -%s", data);
}

static void command_self(const char *data, IRC_SERVER_REC *server)
{
        CMD_IRC_SERVER(server);

	irc_send_cmdv(server, *data == '\0' ? "%s" : "%s %s", current_command, data);
}

static void command_1self(const char *data, IRC_SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (!IS_IRC_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	irc_send_cmdv(server, "%s :%s", current_command, data);
}

static void command_2self(const char *data, IRC_SERVER_REC *server)
{
	char *target, *text;
	void *free_arg;

        CMD_IRC_SERVER(server);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &text))
		return;
	if (*target == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	irc_send_cmdv(server, "%s %s :%s", current_command, target, text);
	cmd_params_free(free_arg);
}

void irc_commands_init(void)
{
	tmpstr = g_string_new(NULL);

	settings_add_str("misc", "part_message", "");
	settings_add_time("misc", "knockout_time", "5min");
	settings_add_str("misc", "wall_format", "[Wall/$0] $1-");
	settings_add_bool("misc", "kick_first_on_kickban", FALSE);
	settings_add_bool("misc", "auto_whowas", TRUE);

	knockout_tag = g_timeout_add(KNOCKOUT_TIMECHECK, (GSourceFunc) knockout_timeout, NULL);

	command_bind_irc("notice", NULL, (SIGNAL_FUNC) cmd_notice);
	command_bind_irc("ctcp", NULL, (SIGNAL_FUNC) cmd_ctcp);
	command_bind_irc("nctcp", NULL, (SIGNAL_FUNC) cmd_nctcp);
	command_bind_irc("part", NULL, (SIGNAL_FUNC) cmd_part);
	command_bind_irc("kick", NULL, (SIGNAL_FUNC) cmd_kick);
	command_bind_irc("topic", NULL, (SIGNAL_FUNC) cmd_topic);
	command_bind_irc("invite", NULL, (SIGNAL_FUNC) cmd_invite);
	command_bind_irc("list", NULL, (SIGNAL_FUNC) cmd_list);
	command_bind_irc("who", NULL, (SIGNAL_FUNC) cmd_who);
	command_bind_irc("names", NULL, (SIGNAL_FUNC) cmd_names);
	command_bind_irc("nick", NULL, (SIGNAL_FUNC) cmd_nick);
	/* SYNTAX: NOTE <command> [&<password>] [+|-<flags>] [<arguments>] */
	command_bind_irc("note", NULL, (SIGNAL_FUNC) command_self);
	command_bind_irc("whois", NULL, (SIGNAL_FUNC) cmd_whois);
	command_bind_irc("whowas", NULL, (SIGNAL_FUNC) cmd_whowas);
	command_bind_irc("ping", NULL, (SIGNAL_FUNC) cmd_ping);
	/* SYNTAX: KILL <nick> <reason> */
	command_bind_irc("kill", NULL, (SIGNAL_FUNC) command_2self);
	command_bind_irc("away", NULL, (SIGNAL_FUNC) cmd_away);
	/* SYNTAX: ISON <nicks> */
	command_bind_irc("ison", NULL, (SIGNAL_FUNC) command_1self);
	command_bind_irc("accept", NULL, (SIGNAL_FUNC) cmd_accept);
	/* SYNTAX: ADMIN [<server>|<nickname>] */
	command_bind_irc("admin", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: INFO [<server>] */
	command_bind_irc("info", NULL, (SIGNAL_FUNC) command_self);
    /* SYNTAX: KNOCK <channel> */
    command_bind_irc("knock", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: LINKS [[<server>] <mask>] */
	command_bind_irc("links", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: LUSERS [<server mask> [<remote server>]] */
	command_bind_irc("lusers", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: MAP */
	command_bind_irc("map", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: MOTD [<server>|<nick>] */
	command_bind_irc("motd", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: REHASH [<option>] */
	command_bind_irc("rehash", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: STATS <type> [<server>] */
	command_bind_irc("stats", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: TIME [<server>|<nick>] */
	command_bind_irc("time", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: TRACE [<server>|<nick>] */
	command_bind_irc("trace", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: VERSION [<server>|<nick>] */
	command_bind_irc("version", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: SERVLIST [<server mask>] */
	command_bind_irc("servlist", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: SILENCE [[+|-]<nick!user@host>]
	           SILENCE [<nick>] */
	command_bind_irc("silence", NULL, (SIGNAL_FUNC) command_self);
	command_bind_irc("unsilence", NULL, (SIGNAL_FUNC) cmd_unsilence);
	command_bind_irc("sconnect", NULL, (SIGNAL_FUNC) cmd_sconnect);
	/* SYNTAX: SQUERY <service> [<commands>] */
	command_bind_irc("squery", NULL, (SIGNAL_FUNC) command_2self);
	/* SYNTAX: DIE */
	command_bind_irc("die", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: HASH */
	command_bind_irc("hash", NULL, (SIGNAL_FUNC) command_self);
	command_bind_irc("oper", NULL, (SIGNAL_FUNC) cmd_oper);
	/* SYNTAX: RESTART */
	command_bind_irc("restart", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: RPING <server> */
	command_bind_irc("rping", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: SQUIT <server>|<mask> <reason> */
	command_bind_irc("squit", NULL, (SIGNAL_FUNC) command_2self);
	/* SYNTAX: UPING <server> */
	command_bind_irc("uping", NULL, (SIGNAL_FUNC) command_self);
	/* SYNTAX: USERHOST <nicks> */
	command_bind_irc("userhost", NULL, (SIGNAL_FUNC) command_self);
	command_bind_irc("quote", NULL, (SIGNAL_FUNC) cmd_quote);
	command_bind_irc("wall", NULL, (SIGNAL_FUNC) cmd_wall);
	command_bind_irc("wait", NULL, (SIGNAL_FUNC) cmd_wait);
	/* SYNTAX: WALLOPS <message> */
	command_bind_irc("wallops", NULL, (SIGNAL_FUNC) command_1self);
	command_bind_irc("kickban", NULL, (SIGNAL_FUNC) cmd_kickban);
	command_bind_irc("knockout", NULL, (SIGNAL_FUNC) cmd_knockout);
	command_bind_irc("server purge", NULL, (SIGNAL_FUNC) cmd_server_purge);

	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("whois try whowas", (SIGNAL_FUNC) sig_whois_try_whowas);
	signal_add("whois event", (SIGNAL_FUNC) event_whois);
	signal_add("whois end", (SIGNAL_FUNC) event_end_of_whois);
	signal_add("whowas event", (SIGNAL_FUNC) event_whowas);

	command_set_options("connect", "+ircnet");
	command_set_options("topic", "delete");
	command_set_options("list", "yes");
	command_set_options("away", "one all");
	command_set_options("whois", "yes");
}

void irc_commands_deinit(void)
{
	g_source_remove(knockout_tag);

	command_unbind("notice", (SIGNAL_FUNC) cmd_notice);
	command_unbind("ctcp", (SIGNAL_FUNC) cmd_ctcp);
	command_unbind("nctcp", (SIGNAL_FUNC) cmd_nctcp);
	command_unbind("part", (SIGNAL_FUNC) cmd_part);
	command_unbind("kick", (SIGNAL_FUNC) cmd_kick);
	command_unbind("topic", (SIGNAL_FUNC) cmd_topic);
	command_unbind("invite", (SIGNAL_FUNC) cmd_invite);
	command_unbind("list", (SIGNAL_FUNC) cmd_list);
	command_unbind("who", (SIGNAL_FUNC) cmd_who);
	command_unbind("names", (SIGNAL_FUNC) cmd_names);
	command_unbind("nick", (SIGNAL_FUNC) cmd_nick);
	command_unbind("note", (SIGNAL_FUNC) command_self);
	command_unbind("whois", (SIGNAL_FUNC) cmd_whois);
	command_unbind("whowas", (SIGNAL_FUNC) cmd_whowas);
	command_unbind("ping", (SIGNAL_FUNC) cmd_ping);
	command_unbind("kill", (SIGNAL_FUNC) command_2self);
	command_unbind("away", (SIGNAL_FUNC) cmd_away);
	command_unbind("ison", (SIGNAL_FUNC) command_1self);
	command_unbind("accept", (SIGNAL_FUNC) cmd_accept);
	command_unbind("admin", (SIGNAL_FUNC) command_self);
	command_unbind("info", (SIGNAL_FUNC) command_self);
    command_unbind("knock", (SIGNAL_FUNC) command_self);
	command_unbind("links", (SIGNAL_FUNC) command_self);
	command_unbind("lusers", (SIGNAL_FUNC) command_self);
	command_unbind("map", (SIGNAL_FUNC) command_self);
	command_unbind("motd", (SIGNAL_FUNC) command_self);
	command_unbind("rehash", (SIGNAL_FUNC) command_self);
	command_unbind("stats", (SIGNAL_FUNC) command_self);
	command_unbind("time", (SIGNAL_FUNC) command_self);
	command_unbind("trace", (SIGNAL_FUNC) command_self);
	command_unbind("version", (SIGNAL_FUNC) command_self);
	command_unbind("servlist", (SIGNAL_FUNC) command_self);
	command_unbind("silence", (SIGNAL_FUNC) command_self);
	command_unbind("unsilence", (SIGNAL_FUNC) cmd_unsilence);
	command_unbind("sconnect", (SIGNAL_FUNC) cmd_sconnect);
	command_unbind("squery", (SIGNAL_FUNC) command_2self);
	command_unbind("die", (SIGNAL_FUNC) command_self);
	command_unbind("hash", (SIGNAL_FUNC) command_self);
	command_unbind("oper", (SIGNAL_FUNC) cmd_oper);
	command_unbind("restart", (SIGNAL_FUNC) command_self);
	command_unbind("rping", (SIGNAL_FUNC) command_self);
	command_unbind("squit", (SIGNAL_FUNC) command_2self);
	command_unbind("uping", (SIGNAL_FUNC) command_self);
	command_unbind("userhost", (SIGNAL_FUNC) command_self);
	command_unbind("quote", (SIGNAL_FUNC) cmd_quote);
	command_unbind("wall", (SIGNAL_FUNC) cmd_wall);
	command_unbind("wait", (SIGNAL_FUNC) cmd_wait);
	command_unbind("wallops", (SIGNAL_FUNC) command_1self);
	command_unbind("kickban", (SIGNAL_FUNC) cmd_kickban);
	command_unbind("knockout", (SIGNAL_FUNC) cmd_knockout);
	command_unbind("server purge", (SIGNAL_FUNC) cmd_server_purge);

	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("whois try whowas", (SIGNAL_FUNC) sig_whois_try_whowas);
	signal_remove("whois event", (SIGNAL_FUNC) event_whois);
	signal_remove("whois end", (SIGNAL_FUNC) event_end_of_whois);
	signal_remove("whowas event", (SIGNAL_FUNC) event_whowas);

	g_string_free(tmpstr, TRUE);
}
