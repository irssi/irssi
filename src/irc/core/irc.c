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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "modules.h"
#include "network.h"
#include "line-split.h"
#include "rawlog.h"

#include "irc.h"
#include "irc-server.h"
#include "channels.h"
#include "server-redirect.h"

char *current_server_event;
static int signal_send_command;
static int signal_default_event;
static int signal_server_event;
static int signal_server_incoming;

static void cmd_send(IRC_SERVER_REC *server, const char *cmd, int send_now, int immediate)
{
	char str[513], *ptr;
	int len, ret;

	server->cmdcount++;

	if (send_now)
		rawlog_output(server->rawlog, cmd);

	/* just check that we don't send any longer commands than 512 bytes.. */
	strncpy(str, cmd, 510);
	len = strlen(cmd);
	if (len > 510) len = 510;
	str[len++] = 13; str[len++] = 10; str[len] = '\0';

	ptr = str;
	if (send_now) {
		ret = net_transmit(server->handle, str, len);
		if (ret == len) {
			g_get_current_time(&server->last_cmd);
			return;
		}

		/* we didn't transmit all data, try again a bit later.. */
		ptr += ret;
		server->cmd_last_split = TRUE;
	}

	/* add to queue */
        ptr = g_strdup(ptr);
	if (!immediate)
		server->cmdqueue = g_slist_append(server->cmdqueue, ptr);
	else if (send_now)
		server->cmdqueue = g_slist_prepend(server->cmdqueue, ptr);
	else
		server->cmdqueue = g_slist_insert(server->cmdqueue, ptr, 1);
}

/* Send command to IRC server */
void irc_send_cmd(IRC_SERVER_REC *server, const char *cmd)
{
	int send_now;

	g_return_if_fail(cmd != NULL);
	if (server == NULL) return;

	send_now = !server->cmd_last_split &&
		(server->cmdcount < server->max_cmds_at_once ||
		 server->cmd_queue_speed <= 0);

        cmd_send(server, cmd, send_now, FALSE);
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
	if (server == NULL) return;

        cmd_send(server, cmd, !server->cmd_last_split, TRUE);
}

static char *split_nicks(const char *cmd, char **pre, char **nicks, char **post, int arg)
{
	char *p;

	*pre = g_strdup(cmd);
	*post = *nicks = NULL;
	for (p = *pre; *p != '\0'; p++) {
		if (!isspace(*p))
			continue;

		if (arg == 1) {
			/* text after nicks */
			*p++ = '\0';
			while (isspace(*p)) p++;
			*post = p;
			break;
		}

		/* find nicks */
		while (isspace(p[1])) p++;
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

	/* split the nicks */
	nickstr = g_string_new(NULL);
	nicklist = g_strsplit(nicks, ",", -1); count = 0;

	tmp = nicklist;
	for (;; tmp++) {
		if (*tmp != NULL) {
			g_string_sprintfa(nickstr, "%s,", *tmp);
			if (++count < max_nicks)
				continue;
		}

		count = 0;
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

/* Nick can be in format "servertag/nick" - Update `nick' to
   position "nick" and return "servertag" which you need to free */
char *irc_nick_get_server(char **nick)
{
	char *ptr, *tag;

	ptr = strchr(*nick, '/');
	if (ptr == NULL) return NULL;
	if (ptr == *nick) {
		(*nick)++;
		return NULL;
	}

        tag = g_strndup(*nick, (int) (ptr-*nick));
	*nick = ptr+1;

	return tag;
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

static void irc_server_event(const char *line, IRC_SERVER_REC *server, const char *nick, const char *address)
{
	char *event, *args, *callcmd;
	GSList *list;

	g_return_if_fail(line != NULL);

	/* get command.. */
	event = g_strconcat("event ", line, NULL);
	args = strchr(event+6, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";
	while (*args == ' ') args++;

	list = server_redirect_getqueue((SERVER_REC *) server, event, args);
	if (list == NULL)
		callcmd = g_strdup(event);
	else {
		/* event is redirected somewhere else.. */
		REDIRECT_REC *rec;

		rec = list->data;
		callcmd = g_strdup(rec->name);
		rawlog_redirect(server->rawlog, callcmd);
		server_redirect_remove_next((SERVER_REC *) server, event, list);
	}

	current_server_event = event+6;
	g_strdown(callcmd);
	if (!signal_emit(callcmd, 4, args, server, nick, address))
		signal_emit_id(signal_default_event, 4, line, server, nick, address);
	current_server_event = NULL;

	g_free(callcmd);
	g_free(event);
}

/* Read line from server */
static int irc_receive_line(SERVER_REC *server, char **str)
{
	char tmpbuf[512];
	int recvlen, ret;

	g_return_val_if_fail(server != NULL, -1);
	g_return_val_if_fail(str != NULL, -1);

	recvlen = net_receive(server->handle, tmpbuf, sizeof(tmpbuf));

	ret = line_split(tmpbuf, recvlen, str, (LINEBUF_REC **) &server->buffer);
	if (ret == -1) {
		/* connection lost */
		server->connection_lost = TRUE;
		server_disconnect(server);
	}
	return ret;
}

static char *irc_parse_prefix(char *line, char **nick, char **address)
{
	*nick = *address = NULL;

	if (*line != ':')
		return line;

	*nick = ++line;
	while (*line != '\0' && *line != ' ') {
		if (*line == '!') {
			*line = '\0';
			*address = line+1;
		}
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
		signal_emit_id(signal_server_event, 4, line, server, nick, address);
}

/* input function: handle incoming server messages */
static void irc_parse_incoming(SERVER_REC *server)
{
	char *str;

	g_return_if_fail(server != NULL);

	while (irc_receive_line(server, &str) > 0) {
		rawlog_input(server->rawlog, str);
		signal_emit_id(signal_server_incoming, 2, server, str);
	}
}

static void irc_init_server(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	server->readtag =
		g_input_add(server->handle, G_INPUT_READ,
			    (GInputFunction) irc_parse_incoming, server);
}

static void irc_deinit_server(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (server->readtag > 0)
		g_source_remove(server->readtag);
}

#define isoptchan(a) \
	(ischannel((a)[0]) || ((a)[0] == '*' && ((a)[1] == '\0' || (a)[1] == ' ')))

static char *irc_cmd_get_func(const char *data, int *count, va_list *vargs)
{
        WI_IRC_REC *item;
	CHANNEL_REC *channel;
	char *ret, *args, *chan, *p;

	if ((*count & PARAM_FLAG_OPTCHAN) == 0)
		return g_strdup(data);

	*count &= ~PARAM_FLAG_OPTCHAN;
	item = (WI_IRC_REC *) va_arg(*vargs, WI_IRC_REC *);
	channel = irc_item_channel(item);

	/* change first argument in data to full channel name. */
	p = args = g_strdup(data);

	chan = isoptchan(args) ? cmd_get_param(&args) : NULL;
	if (chan != NULL && *chan == '!') {
		/* whenever trying to send something to !channel,
		   change it to the real joined !XXXXXchannel */
		channel = channel_find(channel->server, chan);
		if (channel != NULL) chan = channel->name;
	}

	if (chan == NULL || strcmp(chan, "*") == 0) {
		chan = channel == NULL ? "*" : channel->name;
	}

        ret = g_strconcat(chan, " ", args, NULL);
	g_free(p);
	return ret;
}

void irc_irc_init(void)
{
	cmd_get_add_func(irc_cmd_get_func);

	signal_add("server event", (SIGNAL_FUNC) irc_server_event);
	signal_add("server connected", (SIGNAL_FUNC) irc_init_server);
	signal_add_first("server disconnected", (SIGNAL_FUNC) irc_deinit_server);
	signal_add("server incoming", (SIGNAL_FUNC) irc_parse_incoming_line);

	current_server_event = NULL;
	signal_send_command = signal_get_uniq_id("send command");
	signal_default_event = signal_get_uniq_id("default event");
	signal_server_event = signal_get_uniq_id("server event");
	signal_server_incoming = signal_get_uniq_id("server incoming");
}

void irc_irc_deinit(void)
{
	signal_remove("server event", (SIGNAL_FUNC) irc_server_event);
	signal_remove("server connected", (SIGNAL_FUNC) irc_init_server);
	signal_remove("server disconnected", (SIGNAL_FUNC) irc_deinit_server);
	signal_remove("server incoming", (SIGNAL_FUNC) irc_parse_incoming_line);

	module_uniq_destroy("IRC");
	module_uniq_destroy("IRC SERVER");
}
