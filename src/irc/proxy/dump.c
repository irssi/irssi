/*
 dump.c : proxy plugin - output all information about irc session

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "network.h"
#include "settings.h"
#include "irssi-version.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-nicklist.h"
#include "modes.h"

void proxy_outdata(CLIENT_REC *client, const char *data, ...)
{
	va_list args;
	char *str;

	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	net_transmit(client->handle, str, strlen(str));
	g_free(str);

	va_end(args);
}

void proxy_outdata_all(IRC_SERVER_REC *server, const char *data, ...)
{
	va_list args;
	GSList *tmp;
	char *str;
	int len;

	g_return_if_fail(server != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	len = strlen(str);
	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == server)
			net_transmit(rec->handle, str, len);
	}
	g_free(str);

	va_end(args);
}

void proxy_outserver(CLIENT_REC *client, const char *data, ...)
{
	va_list args;
	char *str;

	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	proxy_outdata(client, ":%s!%s@proxy %s\n", client->nick,
		      settings_get_str("user_name"), str);
	g_free(str);

	va_end(args);
}

void proxy_outserver_all(IRC_SERVER_REC *server, const char *data, ...)
{
	va_list args;
	GSList *tmp;
	char *str;

	g_return_if_fail(server != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec->server == server) {
			proxy_outdata(rec, ":%s!%s@proxy %s\n", rec->nick,
				      settings_get_str("user_name"), str);
		}
	}
	g_free(str);

	va_end(args);
}

void proxy_outserver_all_except(CLIENT_REC *client, const char *data, ...)
{
	va_list args;
	GSList *tmp;
	char *str;

	g_return_if_fail(client != NULL);
	g_return_if_fail(data != NULL);

	va_start(args, data);

	str = g_strdup_vprintf(data, args);
	for (tmp = proxy_clients; tmp != NULL; tmp = tmp->next) {
		CLIENT_REC *rec = tmp->data;

		if (rec->connected && rec != client &&
		    rec->server == client->server) {
			proxy_outdata(rec, ":%s!%s@proxy %s\n", rec->nick,
				      settings_get_str("user_name"), str);
		}
	}
	g_free(str);

	va_end(args);
}

static void create_names_start(GString *str, IRC_CHANNEL_REC *channel,
			       CLIENT_REC *client)
{
	g_string_sprintf(str, ":%s 353 %s %c %s :",
			 client->proxy_address, client->nick,
			 channel_mode_is_set(channel, 'p') ? '*' :
			 channel_mode_is_set(channel, 's') ? '@' : '=',
			 channel->name);
}

static void dump_join(IRC_CHANNEL_REC *channel, CLIENT_REC *client)
{
	GSList *tmp, *nicks;
	GString *str;
	int first;

	proxy_outserver(client, "JOIN %s", channel->name);

	str = g_string_new(NULL);
	create_names_start(str, channel, client);

	first = TRUE;
	nicks = nicklist_getnicks(CHANNEL(channel));
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *nick = tmp->data;

		if (str->len >= 500) {
			g_string_append_c(str, '\n');
			proxy_outdata(client, "%s", str->str);
			create_names_start(str, channel, client);
			first = TRUE;
		}

		if (first)
			first = FALSE;
		else
			g_string_append_c(str, ' ');

		if (nick->op)
                        g_string_append_c(str, '@');
		else if (nick->halfop)
                        g_string_append_c(str, '%');
		else if (nick->voice)
                        g_string_append_c(str, '+');
		g_string_append(str, nick->nick);
	}
	g_slist_free(nicks);

	g_string_append_c(str, '\n');
	proxy_outdata(client, "%s", str->str);
	g_string_free(str, TRUE);

	proxy_outdata(client, ":%s 366 %s %s :End of /NAMES list.\n",
		      client->proxy_address, client->nick, channel->name);
	if (channel->topic != NULL) {
		proxy_outdata(client, ":%s 332 %s %s :%s\n",
			      client->proxy_address, client->nick,
			      channel->name, channel->topic);
	}
}

void proxy_client_reset_nick(CLIENT_REC *client)
{
	if (client->server == NULL ||
	    strcmp(client->nick, client->server->nick) == 0)
		return;

	proxy_outdata(client, ":%s!proxy NICK :%s\n",
		      client->nick, client->server->nick);

	g_free(client->nick);
	client->nick = g_strdup(client->server->nick);
}

void proxy_dump_data(CLIENT_REC *client)
{
        proxy_client_reset_nick(client);

	/* welcome info */
	proxy_outdata(client, ":%s 001 %s :Welcome to the Internet Relay Network\n", client->proxy_address, client->nick);
	proxy_outdata(client, ":%s 002 %s :Your host is irssi-proxy, running version %s\n", client->proxy_address, client->nick, IRSSI_VERSION);
	proxy_outdata(client, ":%s 003 %s :This server was created ...\n", client->proxy_address, client->nick);
	if (client->server == NULL || !client->server->emode_known)
		proxy_outdata(client, ":%s 004 %s %s %s oirw abiklmnopqstv\n", client->proxy_address, client->nick, client->proxy_address, IRSSI_VERSION);
	else
		proxy_outdata(client, ":%s 004 %s %s %s oirw abeIiklmnopqstv\n", client->proxy_address, client->nick, client->proxy_address, IRSSI_VERSION);
	proxy_outdata(client, ":%s 251 %s :There are 0 users and 0 invisible on 1 servers\n", client->proxy_address, client->nick);
	proxy_outdata(client, ":%s 255 %s :I have 0 clients, 0 services and 0 servers\n", client->proxy_address, client->nick);
	proxy_outdata(client, ":%s 422 %s :MOTD File is missing\n", client->proxy_address, client->nick);

	/* user mode / away status */
	if (client->server != NULL) {
		if (client->server->usermode != NULL) {
			proxy_outserver(client, "MODE %s :+%s",
					client->server->nick,
					client->server->usermode);
		}
		if (client->server->usermode_away) {
			proxy_outdata(client, ":%s 306 %s :You have been marked as being away\n",
				      client->proxy_address, client->nick);
		}

		/* Send channel joins */
		g_slist_foreach(client->server->channels, (GFunc) dump_join, client);
	}
}
