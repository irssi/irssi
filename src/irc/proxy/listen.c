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
#include "proxy.h"
#include "net-sendbuffer.h"
#include "fe-common/core/printtext.h"
#include "levels.h"

static PLUGIN_DATA *proxy_data;
static GString *next_line;

void remove_client(PLUGIN_DATA *data, CLIENT_REC *rec)
{
    data->clients = g_slist_remove(data->clients, rec);

    net_disconnect(rec->handle);
    g_source_remove(rec->tag);
    line_split_free(rec->buffer);
    g_free(rec);
}

static void proxy_redirect_event(CLIENT_REC *client, gchar *args, gint last, ...)
{
    va_list vargs;
    gchar *event;
    gint argpos, group;
    GString *str;

    g_return_if_fail(client != NULL);

    va_start(vargs, last);

    str = g_string_new(NULL);
    group = 0;
    while ((event = va_arg(vargs, gchar *)) != NULL)
    {
	  argpos = va_arg(vargs, gint);
	  g_string_sprintf(str, "proxy %d", client->handle);
	  group = server_redirect_single_event(client->server, args, last > 0, group, event, str->str, argpos);
	  last--;
    }
    g_string_free(str, TRUE);

    va_end(vargs);
}

static void grab_who(CLIENT_REC *client, gchar *channel)
{
    gchar *chlist;
    gchar **list, **tmp;

    /* /WHO a,b,c may respond with either one "a,b,c End of WHO" message or
       three different "a End of WHO", "b End of WHO", .. messages */
    chlist = g_strdup(channel);
    list = g_strsplit(channel, ",", -1);

    for (tmp = list; *tmp != NULL; tmp++)
    {
	if (strcmp(*tmp, "0") == 0)
	{
	    /* /who 0 displays everyone */
	    **tmp = '*';
	}

	channel = g_strdup_printf("%s %s", chlist, *tmp);
	proxy_redirect_event(client, channel, 2,
			     "event 401", 1, "event 315", 1,
			     "event 352", -1, NULL);
	g_free(channel);
    }
    g_strfreev(list);
    g_free(chlist);
}

static void sig_listen_client(CLIENT_REC *client, gint handle)
{
    char tmpbuf[1024], *str, *cmd, *args, *p;
    int ret, recvlen;

    g_return_if_fail(client != NULL);

    for (;;)
    {
	recvlen = net_receive(handle, tmpbuf, sizeof(tmpbuf));
	ret = line_split(tmpbuf, recvlen, &str, &client->buffer);
        if (ret == -1)
        {
            /* connection lost */
            remove_client(proxy_data, client);
            break;
        }
	if (ret == 0) break;

	if (client->server == NULL)
	    continue;

	cmd = g_strdup(str);
	args = strchr(cmd, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";
	if (*args == ':') args++;
	g_strup(cmd);

	if (!client->connected)
	{
	    if (proxy_data->password != NULL && strcmp(cmd, "PASS") == 0)
	    {
		if (strcmp(proxy_data->password, args) != 0)
		{
		    /* wrong password! */
		    remove_client(proxy_data, client);
                    break;
		}
		client->pass_sent = TRUE;
	    }
	    else if (strcmp(cmd, "NICK") == 0)
		client->nick = g_strdup(args);
	    else if (strcmp(cmd, "USER") == 0)
	    {
		if (client->nick == NULL || (proxy_data->password != NULL && !client->pass_sent))
		{
		    /* stupid client didn't send us NICK/PASS or, kill it */
		    remove_client(proxy_data, client);
		    break;
		}
		client->connected = TRUE;
		plugin_proxy_dump_data(client);
	    }
	}
        else if (strcmp(cmd, "QUIT") == 0)
        {
            remove_client(proxy_data, client);
            break;
        }
	else if (strcmp(cmd, "PING") == 0)
	{
	    net_transmit(handle, "PONG proxy :nick\n", 17);
	}
	else
	{
	    net_transmit(net_sendbuffer_handle(client->server->handle), str, strlen(str));
	    net_transmit(net_sendbuffer_handle(client->server->handle), "\n", 1);

	    if (strcmp(cmd, "WHO") == 0)
	    {
		grab_who(client, args);
	    }
	    else if (strcmp(cmd, "WHOIS") == 0)
	    {
		/* convert dots to spaces */
		for (p = args; *p != '\0'; p++)
		    if (*p == ',') *p = ' ';

		proxy_redirect_event(client, args, 2,
				     "event 318", -1, "event 402", -1,
				     "event 401", 1, "event 311", 1,
				     "event 301", 1, "event 312", 1,
				     "event 313", 1, "event 317", 1,
				     "event 319", 1, NULL);
	    }
	    else if (strcmp(cmd, "ISON") == 0)
	    {
		proxy_redirect_event(client, NULL, 1, "event 303", -1, NULL);
	    }
	    else if (strcmp(cmd, "USERHOST") == 0)
	    {
		proxy_redirect_event(client, args, 1, "event 302", -1, "event 401", 1, NULL);
	    }
	    else if (strcmp(cmd, "MODE") == 0)
	    {
		/* convert dots to spaces */
		gchar *slist, *str, mode;
		gint argc;

		p = strchr(args, ' ');
		if (p != NULL) *p++ = '\0';
		mode = p == NULL ? '\0' : *p;

		slist = g_strdup(args);
		argc = 1;
		for (p = slist; *p != '\0'; p++)
		{
		    if (*p == ',')
		    {
			*p = ' ';
			argc++;
		    }
		}

		/* get channel mode / bans / exception / invite list */
		str = g_strdup_printf("%s %s", args, slist);
		switch (mode)
		{
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
	    }
	}
	g_free(cmd);
    }
}

static void sig_listen(PLUGIN_DATA *data, gint handle)
{
    CLIENT_REC *rec;
    IPADDR ip;
    gint port;

    g_return_if_fail(data != NULL);
    if (servers == NULL) return;

    /* accept connection */
    handle = net_accept(handle, &ip, &port);
    if (handle == -1)
        return;

    rec = g_new0(CLIENT_REC, 1);
    rec->handle = handle;
    rec->server = servers == NULL ? NULL : servers->data;
    rec->tag = g_input_add(handle, G_INPUT_READ, (GInputFunction) sig_listen_client, rec);

    data->clients = g_slist_append(data->clients, rec);
}

static gboolean sig_incoming(SERVER_REC *server, gchar *line)
{
    g_return_val_if_fail(line != NULL, FALSE);

    /* send server event to all clients */
    g_string_sprintf(next_line, "%s\n", line);
    return TRUE;
}

static gboolean sig_server_event(gchar *line, SERVER_REC *server, gchar *nick, gchar *address)
{
    GSList *tmp, *list;
    gchar *event, *args;

    g_return_val_if_fail(line != NULL, FALSE);

    /* get command.. */
    event = g_strconcat("event ", line, NULL);
    args = strchr(event+6, ' ');
    if (args != NULL) *args++ = '\0'; else args = "";
    while (*args == ' ') args++;

    list = server_redirect_getqueue(server, event, args);

    if (list != NULL)
    {
	/* we want to send this to one client (or proxy itself) only */
	REDIRECT_REC *rec;
	gint handle;

	rec = list->data;
	if (g_strncasecmp(rec->name, "proxy ", 6) != 0)
	{
	    /* proxy only */
	    g_free(event);
	    return TRUE;
	}

	if (sscanf(rec->name+6, "%d", &handle) == 1)
	{
            /* send it to specific client only */
	    server_redirect_remove_next(server, event, list);
	    net_transmit(handle, next_line->str, next_line->len);
	    g_free(event);
	    return FALSE;
	}
    }

    if (g_strcasecmp(event, "event ping") == 0)
    {
	/* We want to answer ourself to PINGs.. */
	g_free(event);
	return TRUE;
    }

    /* send the data to clients.. */
    for (tmp = proxy_data->clients; tmp != NULL; tmp = tmp->next)
    {
	CLIENT_REC *rec = tmp->data;

	if (rec->server == server)
	    net_transmit(rec->handle, next_line->str, next_line->len);
    }

    g_free(event);
    return TRUE;
}

static gboolean sig_server_connected(SERVER_REC *server)
{
    GSList *tmp;

    g_return_val_if_fail(server != NULL, FALSE);

    for (tmp = proxy_data->clients; tmp != NULL; tmp = tmp->next)
    {
	CLIENT_REC *rec = tmp->data;

	if (rec->server == NULL)
	    rec->server = server;
    }
    return TRUE;
}

static gboolean sig_server_disconnected(SERVER_REC *server)
{
    GSList *tmp;

    g_return_val_if_fail(server != NULL, FALSE);

    for (tmp = proxy_data->clients; tmp != NULL; tmp = tmp->next)
    {
	CLIENT_REC *rec = tmp->data;

	if (rec->server == server)
	    rec->server = NULL;
    }
    return TRUE;
}

void plugin_proxy_listen_init(PLUGIN_DATA *data)
{
    proxy_data = data;
    g_return_if_fail(proxy_data != NULL);

    next_line = g_string_new(NULL);

    /* start listening */
    proxy_data->listen_handle = net_listen(&proxy_data->ip, &proxy_data->port);
    if (proxy_data->listen_handle == -1)
    {
        printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Listen failed");
        return;
    }

    proxy_data->clients = NULL;
    proxy_data->listen_tag = g_input_add(proxy_data->listen_handle, G_INPUT_READ,
				   (GInputFunction) sig_listen, proxy_data);

    signal_add("server incoming", (SIGNAL_FUNC) sig_incoming);
    signal_add("server event", (SIGNAL_FUNC) sig_server_event);
    signal_add("server connected", (SIGNAL_FUNC) sig_server_connected);
    signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
}

void plugin_proxy_listen_deinit(PLUGIN_DATA *data)
{
    g_return_if_fail(data != NULL);

    g_string_free(next_line, TRUE);
    while (data->clients != NULL)
        remove_client(data, data->clients->data);

    net_disconnect(data->listen_handle);
    g_source_remove(data->listen_tag);
}
