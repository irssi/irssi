/*
 listen.c : sample plugin for irssi

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
#include "signals.h"
#include "net-sendbuffer.h"
#include "servers-redirect.h"
#include "levels.h"
#include "settings.h"

#include "irc.h"
#include "irc-channels.h"

#include "fe-common/core/printtext.h"

GSList *proxy_listens;
GSList *proxy_clients;

static GString *next_line;

static void remove_client(CLIENT_REC *rec)
{
	g_return_if_fail(rec != NULL);

	proxy_clients = g_slist_remove(proxy_clients, rec);

	net_disconnect(rec->handle);
	g_source_remove(rec->tag);
	line_split_free(rec->buffer);
	g_free_not_null(rec->nick);
	g_free(rec);
}

static void proxy_redirect_event(CLIENT_REC *client,
				 const char *args, int last, ...)
{
	va_list vargs;
	GString *str;
	char *event;
	int argpos, group;

	g_return_if_fail(client != NULL);

	va_start(vargs, last);

	str = g_string_new(NULL);
	group = 0;
	while ((event = va_arg(vargs, char *)) != NULL) {
		argpos = va_arg(vargs, int);
		g_string_sprintf(str, "proxy %d", client->handle);
		group = server_redirect_single_event(SERVER(client->server), args, last > 0,
						     group, event, str->str, argpos);
		last--;
	}
	g_string_free(str, TRUE);

	va_end(vargs);
}

static void grab_who(CLIENT_REC *client, const char *channel)
{
	char *chlist, *chanevent;
	char **list, **tmp;

	/* /WHO a,b,c may respond with either one "a,b,c End of WHO" message
	   or three different "a End of WHO", "b End of WHO", .. messages */
	chlist = g_strdup(channel);
	list = g_strsplit(channel, ",", -1);

	for (tmp = list; *tmp != NULL; tmp++) {
		if (strcmp(*tmp, "0") == 0) {
			/* /who 0 displays everyone */
			**tmp = '*';
		}

		chanevent = g_strdup_printf("%s %s", chlist, *tmp);
		proxy_redirect_event(client, chanevent, 2,
				     "event 401", 1, "event 315", 1,
				     "event 352", -1, NULL);
		g_free(chanevent);
	}
	g_strfreev(list);
	g_free(chlist);
}

static void handle_client_connect_cmd(CLIENT_REC *client,
				      const char *cmd, const char *args)
{
	const char *password;

	password = settings_get_str("irssiproxy_password");

	if (password != NULL && strcmp(cmd, "PASS") == 0) {
		if (strcmp(password, args) == 0)
			client->pass_sent = TRUE;
		else {
			/* wrong password! */
			remove_client(client);
		}
	} else if (strcmp(cmd, "NICK") == 0) {
		g_free_not_null(client->nick);
		client->nick = g_strdup(args);
	} else if (strcmp(cmd, "USER") == 0) {
		if (client->nick == NULL ||
		    (*password != '\0' && !client->pass_sent)) {
			/* stupid client didn't send us NICK/PASS, kill it */
			remove_client(client);
		} else {
			client->connected = TRUE;
			plugin_proxy_dump_data(client);
		}
	}
}

static void handle_client_cmd(CLIENT_REC *client, char *cmd, char *args)
{
	int server_handle;

	if (!client->connected) {
		handle_client_connect_cmd(client, cmd, args);
		return;
	}

	if (strcmp(cmd, "QUIT") == 0) {
		remove_client(client);
		return;
	}
	if (strcmp(cmd, "PING") == 0) {
		char *server = strchr(args, ':');
		if (server == NULL || strcmp(server, "proxy") == 0) {
			if (server != NULL) *server = '\0';
			if (*args == '\0') args = client->nick;
			proxy_outdata(client, "PONG proxy :%s\n", args);
			return;
		}
	}

	if (client->server == NULL || !client->server->connected) {
		proxy_outserver(client, "NOTICE %s :Not connected to server",
				client->nick);
                return;
	}

	server_handle = net_sendbuffer_handle(client->server->handle);
	net_transmit(server_handle, cmd, strlen(cmd));
	net_transmit(server_handle, " ", 1);
	net_transmit(server_handle, args, strlen(args));
	net_transmit(server_handle, "\n", 1);

	if (strcmp(cmd, "WHO") == 0)
		grab_who(client, args);
	else if (strcmp(cmd, "WHOIS") == 0) {
		char *p;

		/* convert dots to spaces */
		for (p = args; *p != '\0'; p++)
			if (*p == ',') *p = ' ';

		proxy_redirect_event(client, args, 2,
				     "event 318", -1, "event 402", -1,
				     "event 401", 1, "event 311", 1,
				     "event 301", 1, "event 312", 1,
				     "event 313", 1, "event 317", 1,
				     "event 319", 1, NULL);
	} else if (strcmp(cmd, "ISON") == 0)
		proxy_redirect_event(client, NULL, 1, "event 303", -1, NULL);
	else if (strcmp(cmd, "USERHOST") == 0)
		proxy_redirect_event(client, args, 1, "event 302", -1, "event 401", 1, NULL);
	else if (strcmp(cmd, "MODE") == 0) {
		/* convert dots to spaces */
		char *slist, *str, mode, *p;
		int argc;

		p = strchr(args, ' ');
		if (p != NULL) *p++ = '\0';
		mode = p == NULL ? '\0' : *p;

		slist = g_strdup(args);
		argc = 1;
		for (p = slist; *p != '\0'; p++) {
			if (*p == ',') {
				*p = ' ';
				argc++;
			}
		}

		/* get channel mode / bans / exception / invite list */
		str = g_strdup_printf("%s %s", args, slist);
		switch (mode) {
		case '\0':
			while (argc-- > 0)
				proxy_redirect_event(client, str, 3, "event 403", 1,
						     "event 443", 1, "event 324", 1, NULL);
			break;
		case 'b':
			while (argc-- > 0)
				proxy_redirect_event(client, str, 2, "event 403", 1,
						     "event 368", 1, "event 367", 1, NULL);
			break;
		case 'e':
			while (argc-- > 0)
				proxy_redirect_event(client, str, 4, "event 403", 1,
						     "event 482", 1, "event 472", -1,
						     "event 349", 1, "event 348", 1, NULL);
			break;
		case 'I':
			while (argc-- > 0)
				proxy_redirect_event(client, str, 4, "event 403", 1,
						     "event 482", 1, "event 472", -1,
						     "event 347", 1, "event 346", 1, NULL);
			break;
		}
		g_free(str);
		g_free(slist);
	} else if (strcmp(cmd, "PRIVMSG") == 0) {
		/* send the message to other clients as well */
		char *params, *target, *msg;

		params = event_get_params(args, 2 | PARAM_FLAG_GETREST,
					  &target, &msg);
		proxy_outserver_all_except(client, "PRIVMSG %s", args);
		signal_emit("message public", 5, client->server, msg,
			    client->nick, "proxy", target);
		g_free(params);
	}
}

static void sig_listen_client(CLIENT_REC *client)
{
	char tmpbuf[1024], *str, *cmd, *args;
	int ret, recvlen;

	g_return_if_fail(client != NULL);

	while (g_slist_find(proxy_clients, client) != NULL) {
		recvlen = net_receive(client->handle, tmpbuf, sizeof(tmpbuf));
		ret = line_split(tmpbuf, recvlen, &str, &client->buffer);
		if (ret == -1) {
			/* connection lost */
			remove_client(client);
			break;
		}

		if (ret == 0)
			break;

		cmd = g_strdup(str);
		args = strchr(cmd, ' ');
		if (args != NULL) *args++ = '\0'; else args = "";
		if (*args == ':') args++;
		g_strup(cmd);

		handle_client_cmd(client, cmd, args);

		g_free(cmd);
	}
}

static void sig_listen(LISTEN_REC *listen)
{
	CLIENT_REC *rec;
	IPADDR ip;
	char host[MAX_IP_LEN];
	int port, handle;

	g_return_if_fail(listen != NULL);

	/* accept connection */
	handle = net_accept(listen->handle, &ip, &port);
	if (handle == -1)
		return;
	net_ip2host(&ip, host);

	rec = g_new0(CLIENT_REC, 1);
	rec->listen = listen;
	rec->handle = handle;
	rec->server = IRC_SERVER(server_find_chatnet(listen->ircnet));
	rec->tag = g_input_add(handle, G_INPUT_READ,
			       (GInputFunction) sig_listen_client, rec);

	proxy_clients = g_slist_append(proxy_clients, rec);
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		  "Proxy: Client connected from %s", host);
}

static void sig_incoming(IRC_SERVER_REC *server, const char *line)
{
	g_return_if_fail(line != NULL);

	/* send server event to all clients */
	g_string_sprintf(next_line, "%s\n", line);
}

static void sig_server_event(const char *line, IRC_SERVER_REC *server,
			     const char *nick, const char *address)
{
	GSList *list;
	char *event, *args;

	g_return_if_fail(line != NULL);
	if (!IS_IRC_SERVER(server))
		return;

	/* get command.. */
	event = g_strconcat("event ", line, NULL);
	args = strchr(event+6, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";
	while (*args == ' ') args++;

	list = server_redirect_getqueue(SERVER(server), event, args);

	if (list != NULL) {
		/* we want to send this to one client (or proxy itself) only */
		REDIRECT_REC *rec;
		int handle;

		rec = list->data;
		if (g_strncasecmp(rec->name, "proxy ", 6) != 0) {
			/* proxy only */
			g_free(event);
			return;
		}

		if (sscanf(rec->name+6, "%d", &handle) == 1) {
			/* send it to specific client only */
			server_redirect_remove_next(SERVER(server), event, list);
			net_transmit(handle, next_line->str, next_line->len);
			g_free(event);
                        signal_stop();
			return;
		}
	}

	if (g_strcasecmp(event, "event ping") == 0 ||
	    (g_strcasecmp(event, "event privmsg") == 0 &&
	     strstr(args, " :\001") != NULL) ||
	    (g_strcasecmp(event, "event notice") == 0 &&
	     strstr(args, " :\001IRSSILAG") != NULL)) {
		/* We want to answer ourself to PINGs and CTCPs,
		   also don't let clients see replies to IRSSILAG requests */
		g_free(event);
		return;
	}

	/* send the data to clients.. */
        proxy_outdata_all(server, next_line->str);

	g_free(event);
}

static void event_connected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (!IS_IRC_SERVER(server) || server->connrec->chatnet == NULL)
		return;

	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == NULL &&
		    g_strcasecmp(server->connrec->chatnet, rec->listen->ircnet) == 0) {
			proxy_outserver(rec, "NOTICE %s :Connected to server", rec->nick);
			rec->server = server;
		}
	}
}

static void proxy_server_disconnected(CLIENT_REC *client,
				      IRC_SERVER_REC *server)
{
	GSList *tmp;

	proxy_outdata(client, ":proxy NOTICE %s :Connection lost to server %s\n",
		      client->nick, server->connrec->address);

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		IRC_CHANNEL_REC *rec = tmp->data;

		proxy_outserver(client, "PART %s :Connection lost to server",
				rec->name);
	}
}

static void sig_server_disconnected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (!IS_IRC_SERVER(server))
		return;

	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == server) {
                        proxy_server_disconnected(rec, server);
			rec->server = NULL;
		}
	}
}

static void event_nick(const char *data, IRC_SERVER_REC *server)
{
	GSList *tmp;

	if (*data == ':') data++;
	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == server) {
			g_free(rec->nick);
			rec->nick = g_strdup(data);
		}
	}
}

static LISTEN_REC *find_listen(const char *ircnet, int port)
{
	GSList *tmp;

	for (tmp = proxy_listens; tmp != NULL; tmp = tmp->next) {
		LISTEN_REC *rec = tmp->data;

		if (rec->port == port &&
		    g_strcasecmp(rec->ircnet, ircnet) == 0)
			return rec;
	}

	return NULL;
}

static void add_listen(const char *ircnet, int port)
{
	LISTEN_REC *rec;

	if (port <= 0 || *ircnet == '\0') return;

	rec = g_new0(LISTEN_REC, 1);
	rec->ircnet = g_strdup(ircnet);
	rec->port = port;

	/* start listening */
	rec->handle = net_listen(NULL, &rec->port);
	if (rec->handle == -1) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "Proxy: Listen in port %d failed: %s",
			  rec->port, g_strerror(errno));
		return;
	}

	rec->tag = g_input_add(rec->handle, G_INPUT_READ,
			       (GInputFunction) sig_listen, rec);

        proxy_listens = g_slist_append(proxy_listens, rec);
}

static void remove_listen(LISTEN_REC *rec)
{
	proxy_listens = g_slist_remove(proxy_listens, rec);

	net_disconnect(rec->handle);
	g_source_remove(rec->tag);
	g_free(rec->ircnet);
	g_free(rec);
}

static void read_settings(void)
{
	LISTEN_REC *rec;
	GSList *remove_listens;
	char **ports, **tmp, *ircnet, *port;
	int portnum;

	remove_listens = g_slist_copy(proxy_listens);

	ports = g_strsplit(settings_get_str("irssiproxy_ports"), " ", -1);
	for (tmp = ports; *tmp != NULL; tmp++) {
		ircnet = *tmp;
		port = strchr(ircnet, '=');
		if (port == NULL)
			continue;

		*port++ = '\0';
		portnum = atoi(port);
		if (portnum <=  0)
			continue;

		rec = find_listen(ircnet, portnum);
		if (rec == NULL)
			add_listen(ircnet, portnum);
		else
			remove_listens = g_slist_remove(remove_listens, rec);
	}
	g_strfreev(ports);

	while (remove_listens != NULL) {
                remove_listen(remove_listens->data);
		g_slist_remove(remove_listens, remove_listens->data);
	}
}

void plugin_proxy_listen_init(void)
{
	next_line = g_string_new(NULL);

	proxy_clients = NULL;
	proxy_listens = NULL;
	read_settings();

	signal_add("server incoming", (SIGNAL_FUNC) sig_incoming);
	signal_add("server event", (SIGNAL_FUNC) sig_server_event);
	signal_add("event connected", (SIGNAL_FUNC) event_connected);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("event nick", (SIGNAL_FUNC) event_nick);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void plugin_proxy_listen_deinit(void)
{
	while (proxy_clients != NULL)
		remove_client(proxy_clients->data);
	while (proxy_listens != NULL)
		remove_listen(proxy_listens->data);
	g_string_free(next_line, TRUE);

	signal_remove("server incoming", (SIGNAL_FUNC) sig_incoming);
	signal_remove("server event", (SIGNAL_FUNC) sig_server_event);
	signal_remove("event connected", (SIGNAL_FUNC) event_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
