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
#include "window-item-def.h"

#include "irc.h"
#include "irc-servers.h"
#include "channels.h"
#include "queries.h"

static char *last_privmsg_from;
static char *last_sent_msg, *last_sent_msg_body;
static char *last_join, *last_public_from;

/* last person who sent you a MSG */
static char *expando_lastmsg(SERVER_REC *server, void *item, int *free_ret)
{
	return last_privmsg_from;
}

/* last person to whom you sent a MSG */
static char *expando_lastmymsg(SERVER_REC *server, void *item, int *free_ret)
{
	return last_sent_msg;
}

/* last person to join a channel you are on */
static char *expando_lastjoin(SERVER_REC *server, void *item, int *free_ret)
{
	return last_join;
}

/* last person to send a public message to a channel you are on */
static char *expando_lastpublic(SERVER_REC *server, void *item, int *free_ret)
{
	return last_public_from;
}

/* body of last MSG you sent */
static char *expando_lastmymsg_body(SERVER_REC *server, void *item, int *free_ret)
{
	return last_sent_msg_body;
}

/* current server numeric being processed */
static char *expando_server_numeric(SERVER_REC *server, void *item, int *free_ret)
{
	return current_server_event == NULL ||
		!is_numeric(current_server_event, 0) ? NULL :
		current_server_event;
}

/* channel you were last INVITEd to */
static char *expando_last_invite(SERVER_REC *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = IRC_SERVER(server);

	return ircserver == NULL ? "" : ircserver->last_invite;
}

/* current server name */
static char *expando_servername(SERVER_REC *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver = IRC_SERVER(server);

	return ircserver == NULL ? "" : ircserver->real_address;
}

/* your /userhost $N address (user@host) */
static char *expando_userhost(SERVER_REC *server, void *item, int *free_ret)
{
	IRC_SERVER_REC *ircserver;
	const char *username;
	char hostname[100];

	ircserver = IRC_SERVER(server);

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

static void event_privmsg(const char *data, IRC_SERVER_REC *server,
			  const char *nick, const char *addr)
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

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &target, &msg))
		return;

	if (*target != '\0' && *msg != '\0' &&
	    !ischannel(*target) && isalpha(*target)) {
		g_free_not_null(last_sent_msg);
		g_free_not_null(last_sent_msg_body);
		last_sent_msg = g_strdup(target);
		last_sent_msg_body = g_strdup(msg);
	}

	cmd_params_free(free_arg);
}

static void event_join(const char *data, IRC_SERVER_REC *server,
		       const char *nick, const char *address)
{
	g_return_if_fail(nick != NULL);

	if (g_strcasecmp(nick, server->nick) != 0) {
		g_free_not_null(last_join);
		last_join = g_strdup(nick);
	}
}

void irc_special_vars_init(void)
{
	last_privmsg_from = NULL;
	last_sent_msg = NULL; last_sent_msg_body = NULL;
	last_join = NULL; last_public_from = NULL;

	expando_create(",", expando_lastmsg);
	expando_create(".", expando_lastmymsg);
	expando_create(":", expando_lastjoin);
	expando_create(";", expando_lastpublic);
	expando_create("B", expando_lastmymsg_body);
	expando_create("H", expando_server_numeric);
	expando_create("I", expando_last_invite);
	expando_create("S", expando_servername);
	expando_create("X", expando_userhost);

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
	expando_destroy("B", expando_lastmymsg_body);
	expando_destroy("H", expando_server_numeric);
	expando_destroy("I", expando_last_invite);
	expando_destroy("S", expando_servername);
	expando_destroy("X", expando_userhost);

	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("command msg", (SIGNAL_FUNC) cmd_msg);
}
