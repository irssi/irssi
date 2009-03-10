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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "network.h"
#include "net-sendbuffer.h"
#include "settings.h"
#include "irssi-version.h"
#include "recode.h"

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
	net_sendbuffer_send(client->handle, str, strlen(str));
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
			net_sendbuffer_send(rec->handle, str, len);
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
	g_string_printf(str, ":%s 353 %s %c %s :",
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
	char *recoded;

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

		if (nick->prefixes[0])
                        g_string_append_c(str, nick->prefixes[0]);
		g_string_append(str, nick->nick);
	}
	g_slist_free(nicks);

	g_string_append_c(str, '\n');
	proxy_outdata(client, "%s", str->str);
	g_string_free(str, TRUE);

	proxy_outdata(client, ":%s 366 %s %s :End of /NAMES list.\n",
		      client->proxy_address, client->nick, channel->name);
	if (channel->topic != NULL) {
		/* this is needed because the topic may be encoded into other charsets internaly */
		recoded = recode_out(SERVER(client->server), channel->topic, channel->name);
		proxy_outdata(client, ":%s 332 %s %s :%s\n",
			      client->proxy_address, client->nick,
			      channel->name, recoded);
		g_free(recoded);
		if (channel->topic_time > 0)
			proxy_outdata(client, ":%s 333 %s %s %s %d\n",
			              client->proxy_address, client->nick,
			              channel->name, channel->topic_by, channel->topic_time);
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

static void proxy_dump_data_005(gpointer key, gpointer value, gpointer context)
{
	if (*(char *)value != '\0')
		g_string_append_printf(context, "%s=%s ", (char *)key, (char *)value);
	else
		g_string_append_printf(context, "%s ", (char *)key);
}

void proxy_dump_data(CLIENT_REC *client)
{
	GString *isupport_out, *paramstr;
	char **paramlist, **tmp;
	int count;

	proxy_client_reset_nick(client);

	/* welcome info */
	proxy_outdata(client, ":%s 001 %s :Welcome to the Internet Relay Network %s!%s@proxy\n", client->proxy_address, client->nick, client->nick, settings_get_str("user_name"));
	proxy_outdata(client, ":%s 002 %s :Your host is irssi-proxy, running version %s\n", client->proxy_address, client->nick, PACKAGE_VERSION);
	proxy_outdata(client, ":%s 003 %s :This server was created ...\n", client->proxy_address, client->nick);
	if (client->server == NULL || !client->server->emode_known)
		proxy_outdata(client, ":%s 004 %s %s %s oirw abiklmnopqstv\n", client->proxy_address, client->nick, client->proxy_address, PACKAGE_VERSION);
	else
		proxy_outdata(client, ":%s 004 %s %s %s oirw abeIiklmnopqstv\n", client->proxy_address, client->nick, client->proxy_address, PACKAGE_VERSION);

	if (client->server != NULL && client->server->isupport_sent) {
		isupport_out = g_string_new(NULL);
		g_hash_table_foreach(client->server->isupport, proxy_dump_data_005, isupport_out);
		if (isupport_out->len > 0)
			g_string_truncate(isupport_out, isupport_out->len-1);

		proxy_outdata(client, ":%s 005 %s ", client->proxy_address, client->nick);

		paramstr = g_string_new(NULL);
		paramlist = g_strsplit(isupport_out->str, " ", -1);
		count = 0;
		tmp = paramlist;

		for (;; tmp++) {
			if (*tmp != NULL) {
				g_string_append_printf(paramstr, "%s ", *tmp);
				if (++count < 15)
					continue;
			}

			count = 0;
			if (paramstr->len > 0)
				g_string_truncate(paramstr, paramstr->len-1);
			g_string_append_printf(paramstr, " :are supported by this server\n");
			proxy_outdata(client, "%s", paramstr->str);
			g_string_truncate(paramstr, 0);
			g_string_printf(paramstr, ":%s 005 %s ", client->proxy_address, client->nick);

			if (*tmp == NULL || tmp[1] == NULL)
				break;
		}

		g_string_free(isupport_out, TRUE);
		g_string_free(paramstr, TRUE);
		g_strfreev(paramlist);
	}

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
