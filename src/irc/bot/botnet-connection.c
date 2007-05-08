/*
 botnet-connection.c : IRC bot plugin for irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "net-nonblock.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "line-split.h"
#include "lib-config/iconfig.h"

#include "botnet.h"
#include "bot-users.h"

#define BOTNET_RECONNECT_TIME (60*5)

static int reconnect_tag;

static int sig_reconnect(void)
{
	GSList *tmp;

	for (tmp = botnets; tmp != NULL; tmp = tmp->next) {
		BOTNET_REC *rec = tmp->data;

		if (rec->reconnect)
                        botnet_connect(rec);
	}

	return 1;
}

static void sig_bot_read(BOT_REC *bot)
{
	BOTNET_REC *botnet;
	char tmpbuf[1024], *str;
	int ret, recvlen, reconnect;

	botnet = bot->botnet;
	for (;;) {
		recvlen = bot->handle == NULL ? -1 :
			net_receive(bot->handle, tmpbuf, sizeof(tmpbuf));
		ret = line_split(tmpbuf, recvlen, &str, &bot->buffer);

		if (ret == 0)
			break;
		if (ret == -1) {
			/* connection lost */
                        reconnect = !bot->disconnect && bot->uplink;
			bot_destroy(bot);

			if (reconnect) {
				/* wasn't intentional disconnection from
				   our uplink, reconnect */
				botnet_connect(botnet);
			}
			break;
		}

                fprintf(stderr, "%s\r\n", str);
		signal_emit("botnet event", 2, bot, str);
	}
}

static void connect_downlink(BOTNET_REC *botnet, GIOChannel *handle,
			     IPADDR *ip, const char *host)
{
	BOT_DOWNLINK_REC *downlink;
	BOT_REC *bot;

	g_return_if_fail(botnet != NULL);

	/* identify the bot who's trying to connect.. */
	downlink = bot_downlink_find(botnet, ip, host);
	if (downlink == NULL || downlink->password == NULL) {
		/* unknown bot, close connection /
		   bot didn't have password, don't let it connect to us */
		net_disconnect(handle);
		return;
	}

	bot = g_new0(BOT_REC, 1);
	bot->botnet = botnet;
	bot->link = downlink;
	g_node_append_data(botnet->bots, bot);

	/* connected.. */
	bot->handle = handle;
	bot->read_tag = g_input_add(handle, G_INPUT_READ, (GInputFunction) sig_bot_read, bot);
}

typedef struct {
	char *botnet;
	IPADDR ip;
	GIOChannel *handle;
} BOT_CONNECT_REC;

static void sig_host_got(RESOLVED_NAME_REC *name, BOT_CONNECT_REC *rec)
{
	BOTNET_REC *botnet;

	botnet = botnet_find(rec->botnet);
	if (botnet == NULL || !botnet->connected) {
		/* this botnet isn't connected anymore.. */
		net_disconnect(rec->handle);
	} else {
		connect_downlink(botnet, rec->handle, &rec->ip,
				 name->error ? NULL : name->name);
	}
        g_free(rec->botnet);
	g_free(rec);
}

static void sig_botnet_listen(BOTNET_REC *botnet)
{
	BOT_CONNECT_REC *rec;
	IPADDR ip;
	GIOChannel *handle;

	g_return_if_fail(botnet != NULL);

	/* accept connection */
	handle = net_accept(botnet->listen_handle, &ip, NULL);
	if (handle == NULL)
		return;

	rec = g_new0(BOT_CONNECT_REC, 1);
	rec->botnet = g_strdup(botnet->name);
	memcpy(&rec->ip, &ip, sizeof(IPADDR));
        rec->handle = handle;

	if (!net_gethostbyaddr_nonblock(&ip, (NET_HOST_CALLBACK) sig_host_got, rec)) {
		/* failed for some reason, try without host */
		connect_downlink(botnet, handle, &ip, NULL);
                g_free(rec->botnet);
		g_free(rec);
	}
}

static int botnet_listen(BOTNET_REC *botnet)
{
	IPADDR addr;
	int port;

	g_return_val_if_fail(botnet != NULL, FALSE);

	if (botnet->port <= 0)
		return FALSE;

	port = botnet->port;
	if (botnet->addr == NULL)
		botnet->listen_handle = net_listen(NULL, &port);
	else {
		net_host2ip(botnet->addr, &addr);
		botnet->listen_handle = net_listen(&addr, &port);
	}

	if (botnet->listen_handle == NULL) {
		g_warning("Couldn't start listening botnet\n");
		return FALSE;
	}

	botnet->listen_tag = g_input_add(botnet->listen_handle, G_INPUT_READ,
					 (GInputFunction) sig_botnet_listen, botnet);

	return TRUE;
}

static void sig_botnet_connected(GIOChannel *handle, BOT_UPLINK_REC *uplink)
{
	BOTNET_REC *botnet;
	BOT_REC *bot;

	g_return_if_fail(uplink != NULL);

	botnet = uplink->botnet;

	if (handle == NULL) {
		/* error, try another bot */
		botnet_connect(botnet);
		return;
	}

	/* connected to bot */
	bot = g_new0(BOT_REC, 1);
        bot->botnet = botnet;
	bot->link = uplink;
	bot->uplink = TRUE;

	bot->handle = handle;
	bot->read_tag = g_input_add(handle, G_INPUT_READ, (GInputFunction) sig_bot_read, bot);

	botnet->uplink = bot;
	g_node_append_data(botnet->bots, bot);

	/* send nick/pass */
	bot_send_cmdv(bot, "PASS %s", uplink->password);
	bot_send_cmdv(bot, "NICK %s", botnet->nick);
}

void botnet_connect(BOTNET_REC *botnet)
{
	BOT_REC *bot;
	BOT_UPLINK_REC *uplink, *best;
	GSList *tmp;
	time_t now;

	g_return_if_fail(botnet != NULL);

	botnet->reconnect = FALSE;
	if (botnet->bots == NULL) {
		/* create bot record for us */
		bot = g_new0(BOT_REC, 1);
		bot->botnet = botnet;
		bot->nick = g_strdup(botnet->nick);
		bot->priority = botnet->priority;
		bot->connected = TRUE;
		bot->master = TRUE;

		bot->read_tag = -1;

		botnet->connected = TRUE;
		botnet->master = bot;

		botnet->bots = g_node_new(bot);
	}

	if (botnet->listen_handle == NULL) {
		/* start listening */
		botnet_listen(botnet);
	}

	if (botnet->uplinks == NULL) {
		/* we have no uplinks */
		return;
	}

	/* find some bot where we can try to connect to */
	now = time(NULL);
	uplink = best = NULL;
	for (tmp = botnet->uplinks; tmp != NULL; tmp = tmp->next) {
		uplink = tmp->data;

		if (uplink->last_connect+BOTNET_RECONNECT_TIME > now)
			continue;

		if (uplink->last_connect == 0) {
			/* haven't yet tried to connect to this bot */
			best = uplink;
			break;
		}

		if (best == NULL || uplink->last_connect < best->last_connect)
			best = uplink;
	}

	if (best == NULL) {
		/* reconnect later */
		botnet->reconnect = TRUE;
		return;
	}

	/* connect to uplink */
	best->last_connect = time(NULL);
	net_connect_nonblock(best->host, best->port, NULL, (NET_CALLBACK) sig_botnet_connected, best);
}

static int botnet_send_botinfo(GNode *node, BOT_REC *client)
{
	BOT_REC *parent, *bot;

	bot = node->data;
	parent = node->parent == NULL ? NULL : node->parent->data;
	if (parent == NULL && client->uplink) parent = client;

	bot_send_cmdv(client, "%s - BOTINFO %s %s %d", bot->botnet->nick, bot->nick,
		      parent != NULL ? parent->nick : "-", bot->priority);
	return FALSE;
}

/* send botnet links to specified bot */
static void botnet_send_links(BOT_REC *bot, int downlinks)
{
	GNode *node;

	if (!downlinks) {
		/* send uplinks */
		if (bot->botnet->uplink == NULL)
			return;

		node = g_node_find(bot->botnet->bots, G_IN_ORDER,
				   G_TRAVERSE_ALL, bot->botnet->uplink);
		if (node == NULL)
			return;

		g_node_traverse(node, G_LEVEL_ORDER, G_TRAVERSE_ALL, -1,
				(GNodeTraverseFunc) botnet_send_botinfo, bot);
		return;
	}

        /* send downlinks = all non-uplink nodes */
	for (node = bot->botnet->bots->children; node != NULL; node = node->next) {
		BOT_REC *rec = node->data;

		if (rec == bot || rec->uplink || !rec->connected)
			continue;

		g_node_traverse(node, G_LEVEL_ORDER, G_TRAVERSE_ALL, -1,
				(GNodeTraverseFunc) botnet_send_botinfo, bot);
	}
}

static void botnet_connect_event_uplink(BOT_REC *bot, const char *data)
{
	BOTNET_REC *botnet;
	BOT_REC *ownbot;
	char *str, *p;
	int num;

	botnet = bot->botnet;
	g_return_if_fail(botnet != NULL);

	if (g_strcasecmp(data, "NICKERROR") == 0) {
		/* nick already in use, change it by adding a number
		   at the end of it */
		p = botnet->nick+strlen(botnet->nick);
		while (p > botnet->nick && i_isdigit(p[-1])) p--;
		num = *p == '\0' ? 2 : atoi(p)+1; *p = '\0';
		str = g_strdup_printf("%s%d", botnet->nick, num);
		g_free(botnet->nick); botnet->nick = str;

		ownbot = botnet->bots->data;
		g_free(ownbot->nick); ownbot->nick = g_strdup(str);

		/* try again.. */
		bot_send_cmdv(bot, "NICK %s", botnet->nick);

		return;
	}

	if (g_strcasecmp(data, "CONNECTED") == 0) {
		/* connected, wait for SYNC command */
		bot->connected = TRUE;
		return;
	}

	/* error? what? */
}

static void botnet_event(BOT_REC *bot, const char *data)
{
	BOT_DOWNLINK_REC *downlink;
	char *fname;

	g_return_if_fail(bot != NULL);
	g_return_if_fail(data != NULL);

	if (bot->connected)
		return;

	signal_stop_by_name("botnet event");

	if (bot->uplink) {
		botnet_connect_event_uplink(bot, data);
		return;
	}

	downlink = bot->link;

	if (!bot->pass_ok && g_strncasecmp(data, "PASS ", 5) == 0) {
		/* password sent, check that it matches */
		if (strcmp(data+5, downlink->password) == 0) {
			/* ok, connected! */
                        bot->pass_ok = TRUE;
		} else {
			/* wrong password, disconnect */
			bot_disconnect(bot);
		}
		return;
	}

	if (g_strncasecmp(data, "NICK ", 5) == 0) {
		/* set bot's nick */
		if (!bot->pass_ok) {
			/* password has to be sent before nick, kill the
			   stupid bot. */
			bot_disconnect(bot);
			return;
		}

		if (g_strcasecmp(bot->botnet->nick, data+5) == 0 ||
		    bot_find_nick(bot->botnet, data+5) != NULL) {
			/* nick already exists */
			bot_send_cmd(bot, "NICKERROR");
			return;
		}

		/* set the nick */
		bot->nick = g_strdup(data+5);
		bot->connected = TRUE;
		bot_send_cmd(bot, "CONNECTED");

		/* send info about all the bots that are connected now
		   to this botnet */
		botnet_send_botinfo(bot->botnet->bots, bot);
		botnet_send_links(bot, FALSE);
		botnet_send_links(bot, TRUE);
		bot_send_cmdv(bot, "%s - MASTER %s", bot->botnet->nick, bot->botnet->master->nick);

		/* send our current user configuration */
		fname = g_strdup_printf("%s/users.temp", get_irssi_dir());
		botuser_save(fname);
		botnet_send_file(bot->botnet, bot->nick, fname);
		g_free(fname);

		/* send sync msg */
		bot_send_cmdv(bot, "%s - SYNC", bot->botnet->nick);
		return;
	}

	/* pass/nick not sent yet */
	bot_send_cmd(bot, "ERROR");
}

static void botnet_event_sync(BOT_REC *bot)
{
	/* send our record to host */
	botnet_send_botinfo(bot->botnet->bots, bot);

	/* send our downlinks to host */
	botnet_send_links(bot, TRUE);

	signal_stop_by_name("botnet event");
}

static BOT_REC *bot_add(BOTNET_REC *botnet, const char *nick, const char *parent)
{
	GNode *node;
	BOT_REC *rec;

	g_return_val_if_fail(botnet != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	node = bot_find_nick(botnet, nick);
	if (node != NULL) return node->data;

	node = bot_find_nick(botnet, parent);
	if (node == NULL) return NULL;

	rec = g_new0(BOT_REC, 1);
	rec->botnet = botnet;
	rec->nick = g_strdup(nick);

	rec->read_tag = -1;
	rec->connected = TRUE;

	g_node_append_data(node, rec);
	return rec;
}

static void botnet_event_botinfo(BOT_REC *bot, const char *data, const char *sender)
{
	char *nick, *parent, *priority;
	void *free_arg;
        BOT_REC *rec;

	/*str = g_strdup_printf("BOTINFO %s", data);
	botnet_broadcast(bot->botnet, bot, sender, str);
	g_free(str);*/

	if (!cmd_get_params(data, &free_arg, 3, &nick, &parent, &priority))
		return;
	if (*parent == '-' && parent[1] == '\0')
		parent = NULL;

	if (parent == NULL && bot->botnet->uplink != NULL &&
	    bot->botnet->uplink == bot) {
                /* our uplink */
		if (bot->nick == NULL) bot->nick = g_strdup(nick);
		rec = bot;
	} else {
		rec = bot_add(bot->botnet, nick, parent);
	}

	if (rec != NULL) {
		rec->priority = atoi(priority);
	}
        cmd_params_free(free_arg);
}

static void botnet_event_botquit(BOT_REC *bot, const char *data)
{
	GNode *node;

	node = bot_find_nick(bot->botnet, data);
	if (node != NULL) bot_destroy(node->data);

	signal_stop_by_name("botnet event");
}

static void sig_bot_disconnected(BOT_REC *bot)
{
	BOT_REC *master, *tmpbot;
	GNode *node;
	char *str;

	if (!bot->botnet->connected)
		return;

	if (bot->connected && bot->handle != NULL) {
		/* send notice to rest of the botnet about quit */
		str = g_strdup_printf("BOTQUIT %s", bot->nick);
		botnet_broadcast(bot->botnet, bot, NULL, str);
		g_free(str);
	}

	if (bot->master) {
		/* master quit */
		node = bot_find_path(bot->botnet, bot->nick);
		tmpbot = node == NULL ? NULL : node->data;

		if (tmpbot != NULL && tmpbot->disconnect) {
			/* we lost the connection to master - find new
			   master for the botnet*/
			master = botnet_find_master(bot->botnet, NULL);
			botnet_set_master(bot->botnet, master);

			str = g_strdup_printf("MASTER %s", master->nick);
			botnet_broadcast(bot->botnet, bot, NULL, str);
			g_free(str);
		}
	}
}

static int print_bot(GNode *node)
{
	BOT_REC *bot = node->data;

	fprintf(stderr, "%s %d %d\r\n", bot->nick, bot->connected, bot->disconnect);
	return FALSE;
}

static void cmd_bots(void)
{
	BOTNET_REC *botnet = botnet_find("ircnet");

	fprintf(stderr, "\r\n");
	g_node_traverse(botnet->bots, G_LEVEL_ORDER, G_TRAVERSE_ALL, -1,
			(GNodeTraverseFunc) print_bot, NULL);
}

void botnet_connection_init(void)
{
	reconnect_tag = g_timeout_add(BOTNET_RECONNECT_TIME*1000, (GSourceFunc) sig_reconnect, NULL);

	signal_add("botnet event", (SIGNAL_FUNC) botnet_event);
	signal_add("botnet event sync", (SIGNAL_FUNC) botnet_event_sync);
	signal_add("botnet event botinfo", (SIGNAL_FUNC) botnet_event_botinfo);
	signal_add("botnet event botquit", (SIGNAL_FUNC) botnet_event_botquit);
	signal_add("bot disconnected", (SIGNAL_FUNC) sig_bot_disconnected);
	command_bind("bots", NULL, (SIGNAL_FUNC) cmd_bots);
}

void botnet_connection_deinit(void)
{
	g_source_remove(reconnect_tag);

	signal_remove("botnet event", (SIGNAL_FUNC) botnet_event);
	signal_remove("botnet event sync", (SIGNAL_FUNC) botnet_event_sync);
	signal_remove("botnet event botinfo", (SIGNAL_FUNC) botnet_event_botinfo);
	signal_remove("botnet event botquit", (SIGNAL_FUNC) botnet_event_botquit);
	signal_remove("bot disconnected", (SIGNAL_FUNC) sig_bot_disconnected);
	command_unbind("bots", (SIGNAL_FUNC) cmd_bots);
}
