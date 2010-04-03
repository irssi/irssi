/*
 irc.c : irssi

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
#include "modules.h"
#include "network.h"
#include "net-sendbuffer.h"
#include "rawlog.h"
#include "misc.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "servers-redirect.h"

char *current_server_event;
static int signal_default_event;
static int signal_server_event;
static int signal_server_incoming;

#ifdef BLOCKING_SOCKETS
#  define MAX_SOCKET_READS 1
#else
#  define MAX_SOCKET_READS 5
#endif

/* The core of the irc_send_cmd* functions. If `raw' is TRUE, the `cmd'
   won't be checked at all if it's 512 bytes or not, or if it contains
   line feeds or not. Use with extreme caution! */
void irc_send_cmd_full(IRC_SERVER_REC *server, const char *cmd,
		       int send_now, int immediate, int raw)
{
	char str[513];
	int len;

	g_return_if_fail(server != NULL);
	g_return_if_fail(cmd != NULL);

	if (server->connection_lost)
		return;

	len = strlen(cmd);
	if (server->cmdcount == 0)
		irc_servers_start_cmd_timeout();
	server->cmdcount++;

	if (!raw) {
		/* check that we don't send any longer commands
		   than 510 bytes (2 bytes for CR+LF) */
		strncpy(str, cmd, 510);
		if (len > 510) len = 510;
		str[len] = '\0';
                cmd = str;
	}

	if (send_now) {
		rawlog_output(server->rawlog, cmd);
		server_redirect_command(server, cmd, server->redirect_next);
                server->redirect_next = NULL;
	}

	if (!raw) {
                /* Add CR+LF to command */
		str[len++] = 13;
		str[len++] = 10;
		str[len] = '\0';
	}

	if (send_now) {
                irc_server_send_data(server, cmd, len);
	} else {

		/* add to queue */
		if (immediate) {
			server->cmdqueue = g_slist_prepend(server->cmdqueue,
							   server->redirect_next);
			server->cmdqueue = g_slist_prepend(server->cmdqueue,
							   g_strdup(cmd));
		} else {
			server->cmdqueue = g_slist_append(server->cmdqueue,
							  g_strdup(cmd));
			server->cmdqueue = g_slist_append(server->cmdqueue,
							  server->redirect_next);
		}
	}
        server->redirect_next = NULL;
}

/* Send command to IRC server */
void irc_send_cmd(IRC_SERVER_REC *server, const char *cmd)
{
	GTimeVal now;
	int send_now;

        g_get_current_time(&now);
	send_now = g_timeval_cmp(&now, &server->wait_cmd) >= 0 &&
		(server->cmdcount < server->max_cmds_at_once ||
		 server->cmd_queue_speed <= 0);

        irc_send_cmd_full(server, cmd, send_now, FALSE, FALSE);
}

/* Send command to IRC server */
void irc_send_cmdv(IRC_SERVER_REC *server, const char *cmd, ...)
{
	va_list args;
	char *str;

	va_start(args, cmd);

	str = g_strdup_vprintf(cmd, args);
	irc_send_cmd(server, str);
	g_free(str);

	va_end(args);
}

/* Send command to server immediately bypassing all flood protections
   and queues. */
void irc_send_cmd_now(IRC_SERVER_REC *server, const char *cmd)
{
	g_return_if_fail(cmd != NULL);

        irc_send_cmd_full(server, cmd, TRUE, TRUE, FALSE);
}

/* Send command to server putting it at the beginning of the queue of
    commands to send -- it will go out as soon as possible in accordance
    to the flood protection settings. */
void irc_send_cmd_first(IRC_SERVER_REC *server, const char *cmd)
{
	g_return_if_fail(cmd != NULL);

        irc_send_cmd_full(server, cmd, FALSE, TRUE, FALSE);
}

static char *split_nicks(const char *cmd, char **pre, char **nicks, char **post, int arg)
{
	char *p;

	*pre = g_strdup(cmd);
	*post = *nicks = NULL;
	for (p = *pre; *p != '\0'; p++) {
		if (*p != ' ')
			continue;

		if (arg == 1) {
			/* text after nicks */
			*p++ = '\0';
			while (*p == ' ') p++;
			*post = p;
			break;
		}

		/* find nicks */
		while (p[1] == ' ') p++;
		if (--arg == 1) {
			*p = '\0';
			*nicks = p+1;
		}
	}

	return *pre;
}

void irc_send_cmd_split(IRC_SERVER_REC *server, const char *cmd,
			int nickarg, int max_nicks)
{
	char *str, *pre, *post, *nicks;
	char **nicklist, **tmp;
	GString *nickstr;
	int count;

	g_return_if_fail(server != NULL);
	g_return_if_fail(cmd != NULL);

	str = split_nicks(cmd, &pre, &nicks, &post, nickarg);
	if (nicks == NULL) {
                /* no nicks given? */
		g_free(str);
		return;
	}

	/* split the nicks */
	nickstr = g_string_new(NULL);
	nicklist = g_strsplit(nicks, ",", -1); count = 0;

	tmp = nicklist;
	for (;; tmp++) {
		if (*tmp != NULL) {
			g_string_append_printf(nickstr, "%s,", *tmp);
			if (++count < max_nicks)
				continue;
		}

		count = 0;
		if (nickstr->len > 0)
			g_string_truncate(nickstr, nickstr->len-1);
		irc_send_cmdv(server, post == NULL ? "%s %s" : "%s %s %s",
			      pre, nickstr->str, post);
		g_string_truncate(nickstr, 0);

		if (*tmp == NULL || tmp[1] == NULL)
			break;
	}
	g_strfreev(nicklist);
	g_string_free(nickstr, TRUE);

	g_free(str);
}

/* Get next parameter */
char *event_get_param(char **data)
{
	char *pos;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(*data != NULL, NULL);

	if (**data == ':') {
		/* last parameter */
		pos = *data;
		*data += strlen(*data);
		return pos+1;
	}

	pos = *data;
	while (**data != '\0' && **data != ' ') (*data)++;
	if (**data == ' ') *(*data)++ = '\0';

	return pos;
}

/* Get count parameters from data */
char *event_get_params(const char *data, int count, ...)
{
	char **str, *tmp, *duprec, *datad;
	gboolean rest;
	va_list args;

	g_return_val_if_fail(data != NULL, NULL);

	va_start(args, count);
	duprec = datad = g_strdup(data);

	rest = count & PARAM_FLAG_GETREST;
	count = PARAM_WITHOUT_FLAGS(count);

	while (count-- > 0) {
		str = (char **) va_arg(args, char **);
		if (count == 0 && rest) {
			/* put the rest to last parameter */
			tmp = *datad == ':' ? datad+1 : datad;
		} else {
			tmp = event_get_param(&datad);
		}
		if (str != NULL) *str = tmp;
	}
	va_end(args);

	return duprec;
}

static void irc_server_event(IRC_SERVER_REC *server, const char *line,
			     const char *nick, const char *address)
{
        const char *signal;
	char *event, *args;

	g_return_if_fail(line != NULL);

	/* split event / args */
	event = g_strconcat("event ", line, NULL);
	args = strchr(event+6, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";
	while (*args == ' ') args++;
	ascii_strdown(event);

        /* check if event needs to be redirected */
	signal = server_redirect_get_signal(server, nick, event, args);
	if (signal == NULL)
		signal = event;
        else
		rawlog_redirect(server->rawlog, signal);

        /* emit it */
	current_server_event = event+6;
	if (!signal_emit(signal, 4, server, args, nick, address))
		signal_emit_id(signal_default_event, 4, server, line, nick, address);
	current_server_event = NULL;

	g_free(event);
}

static char *irc_parse_prefix(char *line, char **nick, char **address)
{
	char *p;

	*nick = *address = NULL;

	/* :<nick> [["!" <user>] "@" <host>] SPACE */

	if (*line != ':')
		return line;

	*nick = ++line; p = NULL;
	while (*line != '\0' && *line != ' ') {
		if (*line == '!' || *line == '@') {
			p = line;
			if (*line == '!')
				break;
		}
		line++;
	}

	if (p != NULL) {
		line = p;
		*line++ = '\0';
		*address = line;
		while (*line != '\0' && *line != ' ')
			line++;
	}

	if (*line == ' ') {
		*line++ = '\0';
		while (*line == ' ') line++;
	}

	return line;
}

/* Parse command line sent by server */
static void irc_parse_incoming_line(IRC_SERVER_REC *server, char *line)
{
	char *nick, *address;

	g_return_if_fail(server != NULL);
	g_return_if_fail(line != NULL);

	line = irc_parse_prefix(line, &nick, &address);
	if (*line != '\0')
		signal_emit_id(signal_server_event, 4, server, line, nick, address);
}

/* input function: handle incoming server messages */
static void irc_parse_incoming(SERVER_REC *server)
{
	char *str;
	int count;
	int ret;

	g_return_if_fail(server != NULL);

	/* Some commands can send huge replies and irssi might handle them
	   too slowly, so read only a few times from the socket before
	   letting other tasks to run. */
	count = 0;
	ret = 0;
	server_ref(server);
	while (!server->disconnected &&
	       (ret = net_sendbuffer_receive_line(server->handle, &str, count < MAX_SOCKET_READS)) > 0) {
		rawlog_input(server->rawlog, str);
		signal_emit_id(signal_server_incoming, 2, server, str);

		if (server->connection_lost)
			server_disconnect(server);

		count++;
	}
	if (ret == -1) {
		/* connection lost */
		server->connection_lost = TRUE;
		server_disconnect(server);
	}
	server_unref(server);
}

static void irc_init_server(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	server->readtag =
		g_input_add(net_sendbuffer_handle(server->handle),
			    G_INPUT_READ,
			    (GInputFunction) irc_parse_incoming, server);
}

void irc_irc_init(void)
{
	signal_add("server event", (SIGNAL_FUNC) irc_server_event);
	signal_add("server connected", (SIGNAL_FUNC) irc_init_server);
	signal_add("server incoming", (SIGNAL_FUNC) irc_parse_incoming_line);

	current_server_event = NULL;
	signal_default_event = signal_get_uniq_id("default event");
	signal_server_event = signal_get_uniq_id("server event");
	signal_server_incoming = signal_get_uniq_id("server incoming");
}

void irc_irc_deinit(void)
{
	signal_remove("server event", (SIGNAL_FUNC) irc_server_event);
	signal_remove("server connected", (SIGNAL_FUNC) irc_init_server);
	signal_remove("server incoming", (SIGNAL_FUNC) irc_parse_incoming_line);
}
