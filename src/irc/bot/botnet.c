/*
 botnet.c : IRC bot plugin for irssi

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

void botnet_connection_init(void);
void botnet_connection_deinit(void);

void botnet_users_deinit(void);
void botnet_users_init(void);

GSList *botnets;

void bot_send_cmd(BOT_REC *bot, const char *data)
{
	g_return_if_fail(bot != NULL);
	g_return_if_fail(data != NULL);

	net_transmit(bot->handle, data, strlen(data));
	net_transmit(bot->handle, "\n", 1);
}

void bot_send_cmdv(BOT_REC *bot, const char *format, ...)
{
	va_list args;
	char *str;

	va_start(args, format);

	str = g_strdup_vprintf(format, args);
	bot_send_cmd(bot, str);
	g_free(str);

	va_end(args);
}

static void botnet_broadcast_single(BOTNET_REC *botnet, BOT_REC *except_bot,
				    const char *source, const char *data)
{
	GNode *node;
	char *str;

	g_return_if_fail(botnet != NULL);
	g_return_if_fail(data != NULL);

	str = g_strdup_printf("%s - %s", source != NULL ? source :
			      botnet->nick, data);
	for (node = botnet->bots->children; node != NULL; node = node->next) {
		BOT_REC *rec = node->data;

		if (rec != except_bot && rec->handle != NULL)
			bot_send_cmd(rec, str);
	}
	g_free(str);
}

/* broadcast a message to everyone in bot network, except for `except_bot'
   if it's not NULL. If botnet is NULL, the message is sent to all botnets. */
void botnet_broadcast(BOTNET_REC *botnet, BOT_REC *except_bot,
		      const char *source, const char *data)
{
	GSList *tmp;

	g_return_if_fail(data != NULL);

	if (botnet != NULL) {
		botnet_broadcast_single(botnet, except_bot, source, data);
		return;
	}

	/* broadcast to all botnets */
	for (tmp = botnets; tmp != NULL; tmp = tmp->next) {
		BOTNET_REC *rec = tmp->data;

                botnet_broadcast_single(rec, except_bot, source, data);
	}
}

void botnet_send_cmd(BOTNET_REC *botnet, const char *source,
		     const char *target, const char *data)
{
	GNode *node;
	char *str;

	g_return_if_fail(botnet != NULL);
	g_return_if_fail(target != NULL);
	g_return_if_fail(data != NULL);

	node = bot_find_path(botnet, target);
	if (node == NULL) {
		g_warning("Can't find route for target %s", target);
		return;
	}

	str = g_strdup_printf("%s %s %s", source != NULL ? source :
			      botnet->nick, target, data);
	bot_send_cmd(node->data, str);
	g_free(str);
}

static void escape_buffer(char *buffer, int len)
{
	char *dest, *tempbuf, *p;

	dest = buffer;
	tempbuf = p = g_malloc(len*2+2);
	while (len > 0) {
		if (*buffer == '\0') {
			*p++ = '\\';
			*p++ = '0';
		} else if (*buffer == '\r') {
			*p++ = '\\';
			*p++ = 'r';
		} else if (*buffer == '\n') {
			*p++ = '\\';
			*p++ = 'n';
		} else if (*buffer == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else {
			*p++ = *buffer;
		}
                len--; buffer++;
	}
	*p++ = '\0';

	len = (int) (p-tempbuf);
	memcpy(dest, tempbuf, len);
        g_free(tempbuf);
}

int botnet_send_file(BOTNET_REC *botnet, const char *target, const char *fname)
{
	GNode *node;
	GString *str;
	char buffer[1024];
	int f, len;

	node = bot_find_path(botnet, target);
	if (node == NULL) {
		g_warning("Can't find route for target %s", target);
		return FALSE;
	}

	f = open(fname, O_RDONLY);
	if (f == -1) return FALSE;

	str = g_string_new(NULL);

	g_string_sprintf(str, "%s %s FILE %s", botnet->nick, target, g_basename(fname));
	bot_send_cmd(node->data, str->str);

	while ((len = read(f, buffer, sizeof(buffer)/2-2)) > 0) {
		escape_buffer(buffer, len);

		g_string_sprintf(str, "%s %s FILE %s", botnet->nick, target, buffer);
		bot_send_cmd(node->data, str->str);
	}

	g_string_sprintf(str, "%s %s FILE", botnet->nick, target);
	bot_send_cmd(node->data, str->str);
	g_string_free(str, TRUE);

	close(f);
	return TRUE;
}

BOTNET_REC *botnet_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = botnets; tmp != NULL; tmp = tmp->next) {
		BOTNET_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

typedef struct {
	gconstpointer key;
	int priority;
	GNode *node;
} BOT_FIND_REC;

static int gnode_find_nick(GNode *node, BOT_FIND_REC *rec)
{
	BOT_REC *bot = node->data;

	if (bot == NULL) return FALSE;

	if (bot->nick != NULL && g_strcasecmp(bot->nick, rec->key) == 0) {
		rec->node = node;
		return TRUE;
	}

	return FALSE;
}

GNode *bot_find_nick(BOTNET_REC *botnet, const char *nick)
{
	BOT_FIND_REC rec;

	g_return_val_if_fail(botnet != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec.key = nick;
	rec.node = NULL;
	g_node_traverse(botnet->bots, 0, G_TRAVERSE_ALL, -1,
			(GNodeTraverseFunc) gnode_find_nick, &rec);
	return rec.node;
}

/* Return the bot who we should send the message if we wanted `nick' to get it. */
GNode *bot_find_path(BOTNET_REC *botnet, const char *nick)
{
	BOT_FIND_REC rec;
	GNode *node;

	g_return_val_if_fail(botnet != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	rec.key = nick;
	rec.node = NULL;
	for (node = botnet->bots->children; node != NULL; node = node->next) {
		g_node_traverse(node, 0, G_TRAVERSE_ALL, -1,
				(GNodeTraverseFunc) gnode_find_nick, &rec);
		if (rec.node != NULL) return node;
	}
	return rec.node;
}

/* check if `addr' is an IP address - this is checked to make sure that
   if we have an address like "192.168.0.*", it wouldn't match to host name
   192.168.0.host.org */
static int is_ip_mask(const char *addr)
{
	while (*addr != '\0') {
		if (!i_isdigit(*addr) && *addr != '.' &&
		    *addr != '*' && *addr != '?') return FALSE;
		addr++;
	}

	return TRUE;
}

BOT_DOWNLINK_REC *bot_downlink_find(BOTNET_REC *botnet, IPADDR *ip, const char *host)
{
	GSList *tmp, *tmp2;
	char ipname[MAX_IP_LEN];

	g_return_val_if_fail(botnet != NULL, NULL);
	g_return_val_if_fail(ip != NULL, NULL);

	net_ip2host(ip, ipname);

	for (tmp = botnet->downlinks; tmp != NULL; tmp = tmp->next) {
		BOT_DOWNLINK_REC *rec = tmp->data;

		for (tmp2 = rec->valid_addrs; tmp2 != NULL; tmp2 = tmp2->next) {
			if (match_wildcards(tmp2->data, ipname))
				return rec;
			if (match_wildcards(tmp2->data, host) &&
			    !is_ip_mask(tmp2->data))
				return rec;
		}
	}

	return NULL;
}

static int gnode_find_master(GNode *node, BOT_FIND_REC *rec)
{
	BOT_REC *bot = node->data;

	if (bot == NULL) return FALSE;

	if (!bot->disconnect && bot->priority > rec->priority) {
		rec->node = node;
		return TRUE;
	}

	return FALSE;
}

BOT_REC *botnet_find_master(BOTNET_REC *botnet, BOT_REC *old_master)
{
	BOT_FIND_REC rec;

	g_return_val_if_fail(botnet != NULL, NULL);

	rec.node = NULL;
	rec.priority = old_master == NULL ? -1 : old_master->priority;
	g_node_traverse(botnet->bots, 0, G_TRAVERSE_ALL, -1,
			(GNodeTraverseFunc) gnode_find_master, &rec);
	return rec.node == NULL ? old_master : rec.node->data;
}

void botnet_set_master(BOTNET_REC *botnet, BOT_REC *bot)
{
	g_return_if_fail(botnet != NULL);
	g_return_if_fail(bot != NULL);

	if (botnet->master != NULL)
		botnet->master->master = FALSE;

	bot->master = TRUE;
        botnet->master = bot;
}

void bot_nick_destroy(BOT_CHANNEL_REC *rec, NICK_REC *nick)
{
	g_return_if_fail(rec != NULL);
	g_return_if_fail(nick != NULL);

        rec->nicks = g_slist_remove(rec->nicks, nick);

	g_free(nick->nick);
	g_free_not_null(nick->realname);
	g_free_not_null(nick->host);
	g_free(nick);
}

void bot_channel_destroy(BOT_IRCNET_REC *ircnet, BOT_CHANNEL_REC *rec)
{
	g_return_if_fail(ircnet != NULL);
	g_return_if_fail(rec != NULL);

	ircnet->channels = g_slist_remove(ircnet->channels, rec);

	while (rec->nicks != NULL)
		bot_nick_destroy(rec, rec->nicks->data);

	g_slist_foreach(rec->banlist, (GFunc) g_free, NULL);
	g_slist_foreach(rec->ebanlist, (GFunc) g_free, NULL);
	g_slist_foreach(rec->invitelist, (GFunc) g_free, NULL);

	g_slist_free(rec->banlist);
	g_slist_free(rec->ebanlist);
	g_slist_free(rec->invitelist);

	g_free_not_null(rec->mode);
	g_free_not_null(rec->key);
	g_free(rec->name);
	g_free(rec);
}

void bot_ircnet_destroy(BOT_REC *bot, BOT_IRCNET_REC *rec)
{
	g_return_if_fail(bot != NULL);
	g_return_if_fail(rec != NULL);

	bot->ircnets = g_slist_remove(bot->ircnets, bot);

	while (rec->channels != NULL)
		bot_channel_destroy(rec, rec->channels->data);

	g_free(rec->tag);
        g_free(rec->ircnet);
        g_free(rec->server);
        g_free(rec->nick);
        g_free(rec);
}

void bot_disconnect(BOT_REC *bot)
{
	bot->disconnect = TRUE;

	signal_emit("bot disconnected", 1, bot);

	if (bot->read_tag != -1) {
		g_source_remove(bot->read_tag);
		bot->read_tag = -1;
	}
	if (bot->handle != NULL) {
		net_disconnect(bot->handle);
		bot->handle = NULL;
	}
}

static void bot_mark_disconnect(GNode *node)
{
	BOT_REC *bot = node->data;

	bot->disconnect = TRUE;
}

#define bot_mark_disconnects(node) \
	g_node_traverse(node, G_LEVEL_ORDER, G_TRAVERSE_ALL, -1, \
			(GNodeTraverseFunc) bot_mark_disconnect, NULL)

void bot_destroy(BOT_REC *bot)
{
	GNode *node;

	g_return_if_fail(bot != NULL);

	node = g_node_find(bot->botnet->bots, 0, G_TRAVERSE_ALL, bot);
	if (node != NULL) {
		if (!bot->disconnect)
			bot_mark_disconnects(node);
	}

	bot_disconnect(bot);

	if (node != NULL) {
		while (node->children != NULL)
			bot_destroy(node->children->data);
		g_node_destroy(node);
	}

	if (bot->botnet->uplink == bot)
		bot->botnet->uplink = NULL;
	if (bot->botnet->master == bot)
		bot->botnet->master = NULL;

	while (bot->ircnets != NULL)
		bot_ircnet_destroy(bot, bot->ircnets->data);

	line_split_free(bot->buffer);
	g_free_not_null(bot->nick);
	g_free(bot);
}

void bot_downlink_destroy(BOT_DOWNLINK_REC *rec)
{
	rec->botnet->downlinks = g_slist_remove(rec->botnet->downlinks, rec);

	g_slist_foreach(rec->valid_addrs, (GFunc) g_free, NULL);
	g_slist_free(rec->valid_addrs);

	g_free_not_null(rec->password);
	g_free(rec);
}

void bot_uplink_destroy(BOT_UPLINK_REC *rec)
{
	rec->botnet->uplinks = g_slist_remove(rec->botnet->uplinks, rec);

	g_free(rec->host);
	g_free_not_null(rec->password);
	g_free(rec);
}

void botnet_disconnect(BOTNET_REC *botnet)
{
	botnet->connected = FALSE;

	bot_destroy(botnet->bots->data);
	botnet->bots = NULL;

	if (botnet->listen_tag != -1) {
		g_source_remove(botnet->listen_tag);
		botnet->listen_tag = -1;
	}
	if (botnet->listen_handle != NULL) {
		net_disconnect(botnet->listen_handle);
		botnet->listen_handle = NULL;
	}
}

static void botnet_destroy(BOTNET_REC *botnet)
{
	botnets = g_slist_remove(botnets, botnet);

        while (botnet->uplinks != NULL)
		bot_uplink_destroy(botnet->uplinks->data);
        while (botnet->downlinks != NULL)
		bot_downlink_destroy(botnet->downlinks->data);

	botnet_disconnect(botnet);

	g_free_not_null(botnet->addr);
	g_free(botnet->name);
	g_free(botnet->nick);
	g_free(botnet);
}

static void botnet_event(BOT_REC *bot, const char *data)
{
	char *source, *target, *command, *args, *event;
	void *free_arg;

	if (!bot->connected)
		return;

	if (!cmd_get_params(data, &free_arg, 4 | PARAM_FLAG_GETREST,
			    &source, &target, &command, &args))
		return;

	if (*target == '-' && target[1] == '\0')
		target = NULL;
	g_strdown(command);

	event = g_strconcat("botnet event ", command, NULL);
	signal_emit(event, 4, bot, args, source, target);
	g_free(event);

        cmd_params_free(free_arg);
}

/* broadcast the signal forward */
static void botnet_event_broadcast(BOT_REC *bot, const char *data)
{
	char *source, *target, *command;
	void *free_arg;

	if (!bot->connected)
		return;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			   &source, &target, &command))
		return;

	if (g_strcasecmp(target, bot->botnet->nick) == 0) {
		/* message was for us */
		cmd_params_free(free_arg);
		return;
	}

	if (*target == '-' && target[1] == '\0') {
		/* broadcast */
		botnet_broadcast(bot->botnet, bot, source, command);
	} else {
		/* send to specified target */
                botnet_send_cmd(bot->botnet, source, target, command);
	}

        cmd_params_free(free_arg);
}

static void botnet_event_master(BOT_REC *bot, const char *data, const char *sender)
{
	BOTNET_REC *botnet;
        BOT_REC *master;
	GNode *node;
	char *str;

	botnet = bot->botnet;

	node = bot_find_nick(bot->botnet, data);
	master = node == NULL ? NULL : node->data;
	master = botnet_find_master(bot->botnet, master);
	g_return_if_fail(master != NULL);

	if (node == NULL || node->data != master) {
		/* no, we don't agree with that master -
		   send our own to everyone. */
		bot = NULL;
	}

	botnet_set_master(botnet, master);

	str = g_strdup_printf("MASTER %s", master->nick);
	botnet_broadcast(botnet, bot, sender, str);
	g_free(str);

	signal_stop_by_name("botnet event");
}

static int unescape_data(const char *input, char *output)
{
	int len;

	len = 0;
	while (*input != '\0') {
		if (*input != '\\')
                        *output++ = *input;
		else {
			input++;
			g_return_val_if_fail(*input != '\0', len);
			switch (*input) {
			case '\\':
				*output++ = '\\';
				break;
			case '0':
				*output++ = '\0';
				break;
			case 'r':
				*output++ = '\r';
				break;
			case 'n':
				*output++ = '\n';
				break;
			}
		}
		input++;
                len++;
	}

	return len;
}

static void botnet_event_file(BOT_REC *bot, const char *data, const char *sender, const char *target)
{
	GNode *node;
	char *tempbuf, *str;
	int len;

	if (g_strcasecmp(target, bot->botnet->nick) != 0)
		return;

	node = bot_find_nick(bot->botnet, sender);
	g_return_if_fail(node != NULL);

	bot = node->data;
	if (bot->file_handle <= 0) {
		/* first line - data contains file name */
		str = g_strdup_printf("%s/%s", get_irssi_dir(), data);
		bot->file_handle = open(str, O_CREAT|O_TRUNC|O_WRONLY, 0600);
                g_free(str);
	} else if (*data == '\0') {
		/* no data - end of file */
		if (bot->file_handle > 0) {
			close(bot->file_handle);
			bot->file_handle = -1;
		}
	} else {
		/* file data */
		tempbuf = g_malloc(strlen(data)*2+2);
		len = unescape_data(data, tempbuf);
		write(bot->file_handle, tempbuf, len);
		g_free(tempbuf);
	}
}

static void botnet_config_read_ips(BOT_DOWNLINK_REC *rec, CONFIG_NODE *node)
{
	GSList *tmp;

	g_return_if_fail(rec != NULL);
	g_return_if_fail(node != NULL);

	node = config_node_section(node, "valid_addrs", -1);
	tmp = node == NULL ? NULL : node->value;
	for (; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;
		rec->valid_addrs = g_slist_append(rec->valid_addrs, g_strdup(node->value));
	}
}

static void botnet_config_read_uplink(BOTNET_REC *botnet, CONFIG_NODE *node)
{
	BOT_UPLINK_REC *rec;
	char *value;

	g_return_if_fail(botnet != NULL);
	g_return_if_fail(node != NULL);

	value = config_node_get_str(node, "host", NULL);
	if (value == NULL) return; /* host required */

	rec = g_new0(BOT_UPLINK_REC, 1);
	rec->botnet = botnet;
	rec->host = g_strdup(value);
	rec->port = config_node_get_int(node, "port", DEFAULT_BOTNET_PORT);
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));

	botnet->uplinks = g_slist_append(botnet->uplinks, rec);
}

static void botnet_config_read_downlink(BOTNET_REC *botnet, CONFIG_NODE *node)
{
	BOT_DOWNLINK_REC *rec;

	g_return_if_fail(botnet != NULL);
	g_return_if_fail(node != NULL);

	rec = g_new0(BOT_DOWNLINK_REC, 1);

	botnet_config_read_ips(rec, node);
	if (rec->valid_addrs == NULL) {
		g_free(rec);
		return;
	}

	rec->botnet = botnet;
	rec->password = g_strdup(config_node_get_str(node, "password", NULL));
	botnet->downlinks = g_slist_append(botnet->downlinks, rec);
}

static void botnet_config_read_botnet(CONFIG_NODE *node)
{
	CONFIG_NODE *subnode;
	BOTNET_REC *botnet;
	GSList *tmp;

	g_return_if_fail(node != NULL);

	if (node->key == NULL || node->value == NULL)
		return;

	/* New botnet */
	botnet = g_new0(BOTNET_REC, 1);
	botnet->name = g_strdup(node->key);
	botnet->nick = g_strdup(config_node_get_str(node, "nick", "bot"));
	botnet->priority = config_node_get_int(node, "priority", DEFAULT_BOTNET_PRIORITY);
	botnet->autoconnect = config_node_get_bool(node, "autoconnect", FALSE);

	botnet->addr = g_strdup(config_node_get_str(node, "listen_addr", NULL));
	botnet->port = config_node_get_int(node, "listen_port", DEFAULT_BOTNET_PORT);

	botnet->listen_tag = -1;

	/* read uplinks */
	subnode = config_node_section(node, "uplinks", -1);
	tmp = subnode == NULL ? NULL : subnode->value;
	for (; tmp != NULL; tmp = tmp->next)
		botnet_config_read_uplink(botnet, tmp->data);

	/* read downlinks */
	subnode = config_node_section(node, "downlinks", -1);
	tmp = subnode == NULL ? NULL : subnode->value;
	for (; tmp != NULL; tmp = tmp->next)
		botnet_config_read_downlink(botnet, tmp->data);

	botnets = g_slist_append(botnets, botnet);
}

static void botnet_config_read(void)
{
	CONFIG_REC *config;
	CONFIG_NODE *node;
	GSList *tmp;
	char *fname;

	/* Read botnets from ~/.irssi/botnets */
	fname = g_strdup_printf("%s/botnets", get_irssi_dir());
	config = config_open(fname, -1);
	g_free(fname);

	if (config == NULL)
		return;

	config_parse(config);

	node = config_node_traverse(config, "botnets", FALSE);
	tmp = node == NULL ? NULL : node->value;
	for (; tmp != NULL; tmp = tmp->next)
                botnet_config_read_botnet(tmp->data);
	config_close(config);
}

/* FIXME: this command is just temporary */
static void cmd_botnet(const char *data)
{
	BOTNET_REC *botnet;
	char *str;

	botnet = botnets->data;

	str = g_strdup_printf("BCAST %s", data);
	botnet_broadcast(botnet, NULL, NULL, str);
	g_free(str);
}

static void autoconnect_botnets(void)
{
	GSList *tmp;

	for (tmp = botnets; tmp != NULL; tmp = tmp->next) {
		BOTNET_REC *rec = tmp->data;

		if (rec->autoconnect)
			botnet_connect(rec);
	}
}

void botnet_init(void)
{
	botnet_config_read();
	botnet_connection_init();
	botnet_users_init();

	signal_add("botnet event", (SIGNAL_FUNC) botnet_event);
	signal_add_last("botnet event", (SIGNAL_FUNC) botnet_event_broadcast);
	signal_add("botnet event master", (SIGNAL_FUNC) botnet_event_master);
	signal_add("botnet event file", (SIGNAL_FUNC) botnet_event_file);
	command_bind("botnet", NULL, (SIGNAL_FUNC) cmd_botnet);

	autoconnect_botnets();
}

void botnet_deinit(void)
{
	while (botnets)
		botnet_destroy(botnets->data);

	botnet_connection_deinit();
	botnet_users_deinit();

	signal_remove("botnet event", (SIGNAL_FUNC) botnet_event);
	signal_remove("botnet event", (SIGNAL_FUNC) botnet_event_broadcast);
	signal_remove("botnet event master", (SIGNAL_FUNC) botnet_event_master);
	signal_remove("botnet event file", (SIGNAL_FUNC) botnet_event_file);
	command_unbind("botnet", (SIGNAL_FUNC) cmd_botnet);
}
