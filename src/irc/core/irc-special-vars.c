/*
 irc-special-vars.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "irc.h"
#include "irc-server.h"
#include "channels.h"
#include "query.h"

static char *last_privmsg_from;
static char *last_sent_msg, *last_sent_msg_body;
static char *last_join, *last_public_from;

/* last person who sent you a MSG */
static char *expando_lastmsg(void *server, void *item, int *free_ret)
{
	return last_privmsg_from;
}

/* last person to whom you sent a MSG */
static char *expando_lastmymsg(void *server, void *item, int *free_ret)
{
	return last_sent_msg;
}

/* last person to join a channel you are on */
static char *expando_lastjoin(void *server, void *item, int *free_ret)
{
	return last_join;
}

/* last person to send a public message to a channel you are on */
static char *expando_lastpublic(void *server, void *item, int *free_ret)
{
	return last_public_from;
}

/* text of your AWAY message, if any */
static char *expando_awaymsg(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->away_reason;
}

/* body of last MSG you sent */
static char *expando_lastmymsg_body(void *server, void *item, int *free_ret)
{
	return last_sent_msg_body;
}

/* current channel */
static char *expando_channel(void *server, void *item, int *free_ret)
{
        CHANNEL_REC *channel;

        channel = irc_item_channel(item);
	return channel == NULL ? NULL : channel->name;
}

/* current server numeric being processed */
static char *expando_server_numeric(void *server, void *item, int *free_ret)
{
	return current_server_event == NULL ||
		!is_numeric(current_server_event, 0) ? NULL :
		current_server_event;
}

/* channel you were last INVITEd to */
static char *expando_last_invite(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->last_invite;
}

/* modes of current channel, if any */
static char *expando_chanmode(void *server, void *item, int *free_ret)
{
        CHANNEL_REC *channel;

	channel = irc_item_channel(item);
	if (channel == NULL) return NULL;

	*free_ret = TRUE;
	return channel_get_mode(channel);
}

/* current nickname */
static char *expando_nick(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->nick;
}

/* value of STATUS_OPER if you are an irc operator */
static char *expando_statusoper(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL || !ircserver->server_operator ? "" :
		(char *) settings_get_str("STATUS_OPER");
}

/* if you are a channel operator in $C, expands to a '@' */
static char *expando_chanop(void *server, void *item, int *free_ret)
{
        CHANNEL_REC *channel;

	channel = irc_item_channel(item);
	if (channel == NULL) return NULL;

	return channel->chanop ? "@" : "";
}

/* nickname of whomever you are QUERYing */
static char *expando_query(void *server, void *item, int *free_ret)
{
	QUERY_REC *query;

        query = irc_item_query(item);
	return query == NULL ? NULL : query->nick;
}

/* version of current server */
static char *expando_serverversion(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->version;
}

/* current server name */
static char *expando_servername(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->real_address;
}

/* target of current input (channel or QUERY nickname) */
static char *expando_target(void *server, void *item, int *free_ret)
{
	if (!irc_item_check(item))
		return NULL;

	return ((WI_IRC_REC *) item)->name;
}
/* your /userhost $N address (user@host) */
static char *expando_userhost(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;
	const char *username;
	char hostname[100];

	/* prefer the _real_ /userhost reply */
	if (ircserver != NULL && ircserver->userhost != NULL)
		return ircserver->userhost;

	/* haven't received userhost reply yet. guess something */
	*free_ret = TRUE;
	if (server == NULL)
		username = settings_get_str("user_name");
	else
		username = ircserver->connrec->username;

	if (gethostname(hostname, sizeof(hostname)) != 0 || *hostname == '\0')
		strcpy(hostname, "??");
	return g_strconcat(username, "@", hostname, NULL);;
}

/* value of REALNAME */
static char *expando_realname(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->connrec->realname;
}

/* Server tag */
static char *expando_servertag(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->tag;
}

/* Server ircnet */
static char *expando_ircnet(void *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = server;

	return ircserver == NULL ? "" : ircserver->connrec->ircnet;
}

static void event_privmsg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr)
{
	char *params, *target, *msg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

	if (!ischannel(*target)) {
		g_free_not_null(last_privmsg_from);
		last_privmsg_from = g_strdup(nick);
	} else {
		g_free_not_null(last_public_from);
		last_public_from = g_strdup(nick);
	}

	g_free(params);
}

static void cmd_msg(const char *data, IRC_SERVER_REC *server)
{
	char *target, *msg;
        void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &msg))
		return;
	if (*target != '\0' && *msg != '\0' && !ischannel(*target) && isalpha(*target)) {
		g_free_not_null(last_sent_msg);
		g_free_not_null(last_sent_msg_body);
		last_sent_msg = g_strdup(target);
		last_sent_msg_body = g_strdup(msg);
	}

	cmd_params_free(free_arg);
}

static void event_join(const char *data, IRC_SERVER_REC *server, const char *nick, const char *address)
{
	g_return_if_fail(nick != NULL);

	if (g_strcasecmp(nick, server->nick) != 0) {
		g_free_not_null(last_join);
		last_join = g_strdup(nick);
	}
}

void irc_special_vars_init(void)
{
	settings_add_str("misc", "STATUS_OPER", "*");

	last_privmsg_from = NULL;
	last_sent_msg = NULL; last_sent_msg_body = NULL;
	last_join = NULL; last_public_from = NULL;

	expando_create(",", expando_lastmsg);
	expando_create(".", expando_lastmymsg);
	expando_create(":", expando_lastjoin);
	expando_create(";", expando_lastpublic);
	expando_create("A", expando_awaymsg);
	expando_create("B", expando_lastmymsg_body);
	expando_create("C", expando_channel);
	expando_create("H", expando_server_numeric);
	expando_create("I", expando_last_invite);
	expando_create("M", expando_chanmode);
	expando_create("N", expando_nick);
	expando_create("O", expando_statusoper);
	expando_create("P", expando_chanop);
	expando_create("Q", expando_query);
	expando_create("R", expando_serverversion);
	expando_create("S", expando_servername);
	expando_create("T", expando_target);
	expando_create("X", expando_userhost);
	expando_create("Y", expando_realname);
	expando_create("tag", expando_servertag);
	expando_create("ircnet", expando_ircnet);

	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("event join", (SIGNAL_FUNC) event_join);
	signal_add("command msg", (SIGNAL_FUNC) cmd_msg);
}

void irc_special_vars_deinit(void)
{
	g_free_not_null(last_privmsg_from);
	g_free_not_null(last_sent_msg); g_free_not_null(last_sent_msg_body);
	g_free_not_null(last_join); g_free_not_null(last_public_from);

	expando_destroy(",", expando_lastmsg);
	expando_destroy(".", expando_lastmymsg);
	expando_destroy(":", expando_lastjoin);
	expando_destroy(";", expando_lastpublic);
	expando_destroy("A", expando_awaymsg);
	expando_destroy("B", expando_lastmymsg_body);
	expando_destroy("C", expando_channel);
	expando_destroy("H", expando_server_numeric);
	expando_destroy("I", expando_last_invite);
	expando_destroy("M", expando_chanmode);
	expando_destroy("N", expando_nick);
	expando_destroy("O", expando_statusoper);
	expando_destroy("P", expando_chanop);
	expando_destroy("Q", expando_query);
	expando_destroy("R", expando_serverversion);
	expando_destroy("S", expando_servername);
	expando_destroy("T", expando_target);
	expando_destroy("X", expando_userhost);
	expando_destroy("Y", expando_realname);
	expando_destroy("tag", expando_servertag);
	expando_destroy("ircnet", expando_ircnet);

	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("command msg", (SIGNAL_FUNC) cmd_msg);
}
