/*
 dump.c : proxy plugin - output all information about irc session

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

#include "common.h"
#include "network.h"
#include "servers.h"
#include "irc-servers.h"
#include "channels.h"
#include "modes.h"
#include "nicklist.h"
#include "settings.h"
#include "proxy.h"

static void outdata(gint handle, gchar *data, ...)
{
    va_list args;
    gchar *str;

    va_start(args, data);

    str = g_strdup_vprintf(data, args);
    net_transmit(handle, str, strlen(str));
    g_free(str);

    va_end(args);
}

static void outserver(gint handle, SERVER_REC *server, gchar *data, ...)
{
    va_list args;
    gchar *str;

    va_start(args, data);

    str = g_strdup_vprintf(data, args);
    outdata(handle, ":%s!%s@proxy %s\n", server->nick, settings_get_str("user_name"), str);
    g_free(str);

    va_end(args);
}

void plugin_proxy_dump_data(CLIENT_REC *client)
{
    SERVER_REC *server;
    GSList *tmp, *tmp2, *nicks;
    gint handle;

    handle = client->handle;
    server = servers->data;
    if (strcmp(server->nick, client->nick) != 0)
    {
	/* change nick first so that clients won't try to eg. set their own
	   user mode with wrong nick.. hopefully works with all clients. */
	outdata(handle, ":%s!proxy NICK :%s\n", client->nick, server->nick);
	g_free(client->nick);
	client->nick = g_strdup(server->nick);
    }
    outdata(handle, ":proxy 001 %s :Welcome to the Internet Relay Network\n", client->nick);
    outdata(handle, ":proxy 002 %s :Your host is irssi-proxy, running version %s\n", client->nick, VERSION);
    outdata(handle, ":proxy 003 %s :This server was created ...\n", client->nick);
    if (!IRC_SERVER(server)->emode_known)
	    outdata(handle, ":proxy 004 %s proxy %s oirw abiklmnopqstv\n", client->nick, VERSION);
    else
	    outdata(handle, ":proxy 004 %s proxy %s oirw abeIiklmnopqstv\n", client->nick, VERSION);
    outdata(handle, ":proxy 251 %s :There are 0 users and 0 invisible on 1 servers\n", client->nick);
    outdata(handle, ":proxy 255 %s :I have 0 clients, 0 services and 0 servers\n", client->nick);
    outdata(handle, ":proxy 422 %s :MOTD File is missing\n", client->nick);

    /* nick / mode */
    outserver(handle, server, "MODE %s :+%s", server->nick, IRC_SERVER(server)->usermode);

    if (server->usermode_away)
	outdata(handle, ":proxy 306 %s :You have been marked as being away\n", server->nick);

    /* Send channel joins */
    for (tmp = server->channels; tmp != NULL; tmp = tmp->next)
    {
        CHANNEL_REC *rec = tmp->data;

        outserver(handle, rec->server, "JOIN %s", rec->name);
        outdata(handle, ":proxy 353 %s %c %s :", rec->server->nick,
	        	channel_mode_is_set(IRC_CHANNEL(rec), 'p') ? '*' : 
				channel_mode_is_set(IRC_CHANNEL(rec), 's') ? '@' : '=',
                rec->name);

        nicks = nicklist_getnicks(rec);
        for (tmp2 = nicks; tmp2 != NULL; tmp2 = tmp2->next)
        {
            NICK_REC *nick = tmp2->data;

            if (tmp2 != nicks)
                net_transmit(handle, " ", 1);

            if (nick->op)
                net_transmit(handle, "@", 1);
            else if (nick->voice)
                net_transmit(handle, "+", 1);
            net_transmit(handle, nick->nick, strlen(nick->nick));
	}
	g_slist_free(nicks);
        net_transmit(handle, "\n", 1);

        outdata(handle, ":proxy 366 %s %s :End of /NAMES list.\n", rec->server->nick, rec->name);
        if (rec->topic != NULL)
	    outdata(handle, ":proxy 332 %s %s :%s\n", rec->server->nick, rec->name, rec->topic);
    }
}
