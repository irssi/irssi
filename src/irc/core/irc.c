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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/modules.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/rawlog.h>
#include <irssi/src/core/refstrings.h>

#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/servers-redirect.h>

char *current_server_event;
static int signal_default_event;
static int signal_server_event;
static int signal_server_event_tags;
static int signal_server_incoming;

#ifdef BLOCKING_SOCKETS
#  define MAX_SOCKET_READS 1
#else
#  define MAX_SOCKET_READS 5
#endif

static void strip_params_colon(char *const);

/* The core of the irc_send_cmd* functions. If `raw' is TRUE, the `cmd'
   won't be checked at all if it's 512 bytes or not, or if it contains
   line feeds or not. Use with extreme caution! */
void irc_send_cmd_full(IRC_SERVER_REC *server, const char *cmd, int irc_send_when, int raw)
{
	GString *str;
	int len;
	guint pos;
	gboolean server_supports_tag;

	g_return_if_fail(server != NULL);
	g_return_if_fail(cmd != NULL);

	if (server->connection_lost)
		return;

	str = g_string_sized_new(MAX_IRC_USER_TAGS_LEN + 2 /* `@'+SPACE */ +
				 server->max_message_len + 2 /* CR+LF */ + 1 /* `\0' */);

	if (server->cmdcount == 0)
		irc_servers_start_cmd_timeout();
	server->cmdcount++;

	pos = g_slist_length(server->cmdqueue);
	if (server->cmdlater > pos / 2) {
		server->cmdlater = pos / 2;
		pos = 0;
	} else {
		pos -= 2 * server->cmdlater;
	}

	if (!raw) {
		const char *tmp = cmd;

		server_supports_tag = server->cap_supported != NULL &&
			g_hash_table_lookup_extended(server->cap_supported, CAP_MESSAGE_TAGS, NULL, NULL);

		if (*cmd == '@' && server_supports_tag) {
			const char *end;

			while (*tmp != ' ' && *tmp != '\0')
				tmp++;

			end = tmp;

			if (tmp - cmd > MAX_IRC_USER_TAGS_LEN) {
				g_warning("irc_send_cmd_full(); tags too long(%ld)", tmp - cmd);
				while (tmp - cmd > MAX_IRC_USER_TAGS_LEN && cmd != tmp - 1) tmp--;
				while (*tmp != ',' && cmd != tmp - 1) tmp--;
			}
			if (cmd != tmp)
				g_string_append_len(str, cmd, tmp - cmd);

			tmp = end;
			while (*tmp == ' ') tmp++;

			if (*tmp != '\0' && str->len > 0)
				g_string_append_c(str, ' ');
		}
		len = strlen(tmp);

		/* check that we don't send any longer commands
		   than 510 bytes (2 bytes for CR+LF) */
		g_string_append_len(str, tmp, len > server->max_message_len ?
				    server->max_message_len : len);
	} else {
		g_string_append(str, cmd);
	}

	if (!raw) {
		/* Add CR+LF to command */
		g_string_append(str, "\r\n");
	}

	if (irc_send_when == IRC_SEND_NOW) {
		irc_server_send_and_redirect(server, str, server->redirect_next);
		g_string_free(str, TRUE);
	} else if (irc_send_when == IRC_SEND_NEXT) {
		/* add to queue */
		server->cmdqueue = g_slist_prepend(server->cmdqueue, server->redirect_next);
		server->cmdqueue = g_slist_prepend(server->cmdqueue, g_string_free(str, FALSE));
	} else if (irc_send_when == IRC_SEND_NORMAL) {
		server->cmdqueue = g_slist_insert(server->cmdqueue, server->redirect_next, pos);
		server->cmdqueue = g_slist_insert(server->cmdqueue, g_string_free(str, FALSE), pos);
	} else if (irc_send_when == IRC_SEND_LATER) {
		server->cmdqueue = g_slist_append(server->cmdqueue, g_string_free(str, FALSE));
		server->cmdqueue = g_slist_append(server->cmdqueue, server->redirect_next);
		server->cmdlater++;
	} else {
		g_warn_if_reached();
	}

	server->redirect_next = NULL;
}

/* Send command to IRC server */
void irc_send_cmd(IRC_SERVER_REC *server, const char *cmd)
{
	gint64 now;
	int send_now;

	now = g_get_real_time();
	send_now = now >= server->wait_cmd &&
	           (server->cmdcount < server->max_cmds_at_once ||
		    server->cmd_queue_speed <= 0);

	irc_send_cmd_full(server, cmd, send_now ? IRC_SEND_NOW : IRC_SEND_NORMAL, FALSE);
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

	irc_send_cmd_full(server, cmd, IRC_SEND_NOW, FALSE);
}

/* Send command to server putting it at the beginning of the queue of
    commands to send -- it will go out as soon as possible in accordance
    to the flood protection settings. */
void irc_send_cmd_first(IRC_SERVER_REC *server, const char *cmd)
{
	g_return_if_fail(cmd != NULL);

	irc_send_cmd_full(server, cmd, IRC_SEND_NEXT, FALSE);
}

/* Send command to server putting it at the end of the queue. */
void irc_send_cmd_later(IRC_SERVER_REC *server, const char *cmd)
{
	g_return_if_fail(cmd != NULL);

	irc_send_cmd_full(server, cmd, IRC_SEND_LATER, FALSE);
}

static char *split_nicks(const char *cmd, char **pre, char **nicks, char **post, int arg)
{
	char *p;

	*pre = g_strdup(cmd);
	*post = *nicks = NULL;

	if (**pre == '@') {
		/* the message-tags "add" one space separated argument
		   in front of the non message-tagged IRC commands. So
		   the nicks are now off-set by one to the right. */
		arg++;
	}

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

		if (post == NULL)
			irc_send_cmdv(server, "%s %s", pre, nickstr->str);
		else
			irc_send_cmdv(server, "%s %s %s", pre, nickstr->str, post);

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
			/* Put the rest into the last parameter. */
			strip_params_colon(datad);
			tmp = datad;
		} else {
			tmp = event_get_param(&datad);
		}
		if (str != NULL) *str = tmp;
	}
	va_end(args);

	return duprec;
}

/* Given a string containing <params>, strip any colon prefixing <trailing>. */
static void strip_params_colon(char *const params)
{
	char *s;

	if (params == NULL) {
		return;
	}

	s = params;
	while (*s != '\0') {
		if (*s == ':') {
			memmove(s, s+1, strlen(s+1)+1);
			return;
		}

		s = strchr(s, ' ');
		if (s == NULL) {
			return;
		}

		while (*s == ' ') {
			s++;
		}
	}
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

static void unescape_tag(char *tag)
{
	char *tmp;

	if (tag == NULL)
		return;

	tmp = tag;
	for (; *tmp != '\0'; tmp++, tag++) {
		if (*tmp == '\\') {
			tmp++;
			if (*tmp == '\0')
				break;
			switch (*tmp) {
			case ':':
				*tag = ';';
				break;
			case 'n':
				*tag = '\n';
				break;
			case 'r':
				*tag = '\r';
				break;
			case 's':
				*tag = ' ';
				break;
			default:
				*tag = *tmp;
				break;
			}
		} else {
			*tag = *tmp;
		}
	}
	*tag = '\0';
}

static gboolean i_str0_equal(const char *s1, const char *s2)
{
	return g_strcmp0(s1, s2) == 0;
}

GHashTable *irc_parse_message_tags(const char *tags)
{
	char **split, **tmp, **kv;
	GHashTable *hash;

	hash = g_hash_table_new_full(g_str_hash, (GEqualFunc) i_str0_equal,
	                             (GDestroyNotify) i_refstr_release, (GDestroyNotify) g_free);
	split = g_strsplit(tags, ";", -1);
	for (tmp = split; *tmp != NULL; tmp++) {
		if (*tmp[0] == '\0')
			continue;
		kv = g_strsplit(*tmp, "=", 2);
		unescape_tag(kv[1]);
		g_hash_table_replace(hash, i_refstr_intern(kv[0]),
		                     g_strdup(kv[1] == NULL ? "" : kv[1]));
		g_strfreev(kv);
	}
	g_strfreev(split);
	return hash;
}

static void irc_server_event_tags(IRC_SERVER_REC *server, const char *line, const char *nick,
                                  const char *address, const char *tags)
{
	char *timestr;
	GHashTable *tags_hash = NULL;

	if (tags != NULL && *tags != '\0') {
		tags_hash = irc_parse_message_tags(tags);
		if ((timestr = g_hash_table_lookup(tags_hash, "time")) != NULL) {
			server_meta_stash(SERVER(server), "time", timestr);
		}
	}

	if (*line != '\0')
		signal_emit_id(signal_server_event, 4, server, line, nick, address);

	if (tags_hash != NULL)
		g_hash_table_destroy(tags_hash);
}

static char *irc_parse_prefix(char *line, char **nick, char **address, char **tags)
{
	char *p;

	*nick = *address = *tags = NULL;

	/* ["@" <tags> SPACE] :<nick> [["!" <user>] "@" <host>] SPACE */

	if (*line == '@') {
		*tags = ++line;
		while (*line != '\0' && *line != ' ') {
			line++;
		}
		if (*line == ' ') {
			*line++ = '\0';
			while (*line == ' ') line++;
		}
	}

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
	char *nick, *address, *tags;

	g_return_if_fail(server != NULL);
	g_return_if_fail(line != NULL);

	line = irc_parse_prefix(line, &nick, &address, &tags);
	if (*line != '\0' || tags != NULL)
		signal_emit_id(signal_server_event_tags, 5, server, line, nick, address, tags);

	server_meta_clear_all(SERVER(server));
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

	server->readtag = i_input_add(net_sendbuffer_handle(server->handle), I_INPUT_READ,
	                              (GInputFunction) irc_parse_incoming, server);
}

void irc_irc_init(void)
{
	signal_add("server event", (SIGNAL_FUNC) irc_server_event);
	signal_add("server event tags", (SIGNAL_FUNC) irc_server_event_tags);
	signal_add("server connected", (SIGNAL_FUNC) irc_init_server);
	signal_add("server connection switched", (SIGNAL_FUNC) irc_init_server);
	signal_add("server incoming", (SIGNAL_FUNC) irc_parse_incoming_line);

	current_server_event = NULL;
	signal_default_event = signal_get_uniq_id("default event");
	signal_server_event = signal_get_uniq_id("server event");
	signal_server_event_tags = signal_get_uniq_id("server event tags");
	signal_server_incoming = signal_get_uniq_id("server incoming");
}

void irc_irc_deinit(void)
{
	signal_remove("server event", (SIGNAL_FUNC) irc_server_event);
	signal_remove("server event tags", (SIGNAL_FUNC) irc_server_event_tags);
	signal_remove("server connected", (SIGNAL_FUNC) irc_init_server);
	signal_remove("server connection switched", (SIGNAL_FUNC) irc_init_server);
	signal_remove("server incoming", (SIGNAL_FUNC) irc_parse_incoming_line);
}
