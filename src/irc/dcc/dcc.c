/*
 dcc.c : irssi

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
#include "signals.h"
#include "commands.h"
#include "network.h"
#include "misc.h"
#include "settings.h"
#include "ignore.h"
#include "levels.h"

#include "irc-servers.h"
#include "servers-setup.h"

#include "dcc-chat.h"
#include "dcc-get.h"
#include "dcc-send.h"
#include "dcc-server.h"

void dcc_resume_init(void);
void dcc_resume_deinit(void);

void dcc_autoget_init(void);
void dcc_autoget_deinit(void);

GSList *dcc_conns;

static GSList *dcc_types;
static int dcc_timeouttag;

void dcc_register_type(const char *type)
{
        dcc_types = g_slist_append(dcc_types, g_strdup(type));
}

void dcc_unregister_type(const char *type)
{
	GSList *pos;

	pos = gslist_find_string(dcc_types, type);
	if (pos != NULL) {
		g_free(pos->data);
                dcc_types = g_slist_remove(dcc_types, pos->data);
	}
}

int dcc_str2type(const char *str)
{
	if (gslist_find_string(dcc_types, str) == NULL)
		return -1;

        return module_get_uniq_id_str("DCC", str);
}

/* Initialize DCC record */
void dcc_init_rec(DCC_REC *dcc, IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
		  const char *nick, const char *arg)
{
	g_return_if_fail(dcc != NULL);
	g_return_if_fail(nick != NULL);
	g_return_if_fail(arg != NULL);

        MODULE_DATA_INIT(dcc);
	dcc->created = time(NULL);
	dcc->chat = chat;
	dcc->arg = g_strdup(arg);
	dcc->nick = g_strdup(nick);
	dcc->tagconn = dcc->tagread = dcc->tagwrite = -1;
	dcc->server = server;
	dcc->mynick = g_strdup(server != NULL ? server->nick :
			       chat != NULL ? chat->nick : "??");

	dcc->servertag = server != NULL ? g_strdup(server->tag) :
		(chat == NULL ? NULL : g_strdup(chat->servertag));
	
	dcc->pasv_id = -1; /* Not a passive DCC */
	
	dcc_conns = g_slist_append(dcc_conns, dcc);
	signal_emit("dcc created", 1, dcc);
}

/* Destroy DCC record */
void dcc_destroy(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);
	if (dcc->destroyed) return;

	dcc_conns = g_slist_remove(dcc_conns, dcc);

	dcc->destroyed = TRUE;
	signal_emit("dcc destroyed", 1, dcc);

	if (dcc->handle != NULL) net_disconnect(dcc->handle);
	if (dcc->tagconn != -1) g_source_remove(dcc->tagconn);
	if (dcc->tagread != -1) g_source_remove(dcc->tagread);
	if (dcc->tagwrite != -1) g_source_remove(dcc->tagwrite);

        MODULE_DATA_DEINIT(dcc);
	g_free_not_null(dcc->servertag);
	g_free_not_null(dcc->target);
	g_free(dcc->mynick);
	g_free(dcc->nick);
	g_free(dcc->arg);
	g_free(dcc);
}

DCC_REC *dcc_find_request_latest(int type)
{
	DCC_REC *latest;
        GSList *tmp;

        latest = NULL;
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->type == type && dcc_is_waiting_user(dcc))
			latest = dcc;
	}

        return latest;
}

DCC_REC *dcc_find_request(int type, const char *nick, const char *arg)
{
	GSList *tmp;

	g_return_val_if_fail(nick != NULL, NULL);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->type == type && !dcc_is_connected(dcc) &&
		    g_strcasecmp(dcc->nick, nick) == 0 &&
		    (arg == NULL || strcmp(dcc->arg, arg) == 0))
			return dcc;
	}

	return NULL;
}

void dcc_ip2str(IPADDR *ip, char *host)
{
	IPADDR temp_ip;
	guint32 addr;

	if (*settings_get_str("dcc_own_ip") != '\0') {
                /* overridden IP address */
		net_host2ip(settings_get_str("dcc_own_ip"), &temp_ip);
                ip = &temp_ip;
	}

	if (IPADDR_IS_V6(ip)) {
		/* IPv6 */
		net_ip2host(ip, host);
	} else {
		memcpy(&addr, &ip->ip, sizeof(addr));
		g_snprintf(host, MAX_IP_LEN, "%lu",
			   (unsigned long) htonl(addr));
	}
}

void dcc_str2ip(const char *str, IPADDR *ip)
{
	guint32 addr;

	if (strchr(str, ':') == NULL) {
		/* normal IPv4 address in 32bit number form */
                addr = strtoul(str, NULL, 10);
		ip->family = AF_INET;
		addr = (guint32) ntohl(addr);
		memcpy(&ip->ip, &addr, sizeof(addr));
	} else {
		/* IPv6 - in standard form */
		net_host2ip(str, ip);
	}
}

/* Start listening for incoming connections */
GIOChannel *dcc_listen(GIOChannel *iface, IPADDR *ip, int *port)
{
        GIOChannel *handle;
	IPADDR *listen_ip = NULL;
	const char *dcc_port, *p, *own_ip;
	int first, last;

	if (net_getsockname(iface, ip, NULL) == -1)
		return NULL;

	/* figure out if we want to listen in IPv4 address or in "any" address,
	   which may mean IPv4+IPv6 or just IPv6 depending on OS. */
	own_ip = settings_get_str("dcc_own_ip");
	if (*own_ip != '\0') {
		if (is_ipv4_address(own_ip))
			listen_ip = &ip4_any;
	} else {
		if (!IPADDR_IS_V6(ip))
			listen_ip = &ip4_any;
	}

        /* get first port */
	dcc_port = settings_get_str("dcc_port");
	first = atoi(dcc_port);
	if (first == 0) {
                /* random port */
		*port = 0;
		return net_listen(listen_ip, port);
	}

        /* get last port */
	p = strchr(dcc_port, ' ');
	if (p == NULL) p = strchr(dcc_port, '-');

	dcc_port = p;
	if (dcc_port == NULL)
		last = first;
	else {
		last = atoi(dcc_port+1);
		if (last == 0)
			last = first;
	}

        /* use the first available port */
	for (*port = first; *port <= last; (*port)++) {
		handle = net_listen(listen_ip, port);
		if (handle != NULL)
                        return handle;
	}

        return NULL;
}

/* Connect to specified IP address using the correct own_ip. */
GIOChannel *dcc_connect_ip(IPADDR *ip, int port)
{
	IPADDR *own_ip, temp_ip;
	const char *own_ip_str;
	GIOChannel *handle;

	own_ip_str = settings_get_str("dcc_own_ip");
	own_ip = NULL;
	if (*own_ip_str != '\0') {
                /* use the specified interface for connecting */
		net_host2ip(own_ip_str, &temp_ip);
		if (IPADDR_IS_V6(ip) == IPADDR_IS_V6(&temp_ip))
			own_ip = &temp_ip;
	}

	if (own_ip == NULL)
		own_ip = IPADDR_IS_V6(ip) ? source_host_ip6 : source_host_ip4;

	handle = net_connect_ip(ip, port, own_ip);
	if (handle == NULL && errno == EADDRNOTAVAIL && own_ip != NULL) {
		/* dcc_own_ip is external address */
		own_ip = IPADDR_IS_V6(ip) ? source_host_ip6 : source_host_ip4;
		handle = net_connect_ip(ip, port, own_ip);
	}
	return handle;
}

/* Server connected - update server for DCC records that have
   the same server tag */
static void sig_connected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	g_return_if_fail(server != NULL);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->server == NULL && dcc->servertag != NULL &&
		    g_strcasecmp(dcc->servertag, server->tag) == 0) {
			dcc->server = server;
			g_free(dcc->mynick);
			dcc->mynick = g_strdup(server->nick);
		}
	}
}

/* Server disconnected, remove it from all DCC records */
static void sig_server_disconnected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	g_return_if_fail(server != NULL);

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->server == server)
                        dcc->server = NULL;
	}
}

/* Your nick changed, change nick in all DCC records */
static void sig_server_nick_changed(IRC_SERVER_REC *server)
{
        GSList *tmp;

        if (!IS_IRC_SERVER(server)) return;

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->server == server) {
			g_free(dcc->mynick);
			dcc->mynick = g_strdup(server->nick);
		}
	}
}

/* handle emitting "ctcp msg dcc" signal - don't use it directly because
   with /IGNORE * CTCPS we'd be ignored */
static void ctcp_msg(IRC_SERVER_REC *server, const char *data,
		     const char *nick, const char *addr, const char *target)
{
	if (g_ascii_strncasecmp(data, "dcc ", 4) != 0)
                return;
	data += 4;

	signal_emit("ctcp msg dcc", 5, server, data, nick, addr, target);
        signal_stop();
}

/* handle emitting "ctcp reply dcc" signal - don't use it directly because
   with /IGNORE * CTCPS we'd be ignored */
static void ctcp_reply(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr, const char *target)
{
	if (g_ascii_strncasecmp(data, "dcc ", 4) != 0)
                return;
	data += 4;

	signal_emit("ctcp reply dcc", 5, server, data, nick, addr, target);
        signal_stop();
}

/* Handle incoming DCC CTCP messages - either from IRC server or DCC chat */
static void ctcp_msg_dcc(IRC_SERVER_REC *server, const char *data,
			 const char *nick, const char *addr,
			 const char *target, DCC_REC *chat)
{
	char *args, *str;

	if (ignore_check(SERVER(server), nick, addr, target, data, MSGLEVEL_DCC))
		return;

	str = g_strconcat("ctcp msg dcc ", data, NULL);
	args = strchr(str+13, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	ascii_strdown(str+13);
	if (!signal_emit(str, 6, server, args, nick, addr, target, chat)) {
		signal_emit("default ctcp msg dcc", 6,
			    server, data, nick, addr, target, chat);
	}
	g_free(str);
}

/* Handle incoming DCC CTCP replies - either from IRC server or DCC chat */
static void ctcp_reply_dcc(IRC_SERVER_REC *server, const char *data,
			   const char *nick, const char *addr,
			   const char *target)
{
	char *args, *str;

	if (ignore_check(SERVER(server), nick, addr, target, data, MSGLEVEL_DCC))
		return;

	str = g_strconcat("ctcp reply dcc ", data, NULL);
	args = strchr(str+15, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	ascii_strdown(str+15);
	if (!signal_emit(str, 5, server, args, nick, addr, target)) {
		signal_emit("default ctcp reply dcc", 5,
			    server, data, nick, addr, target);
	}
	g_free(str);
}

/* CTCP REPLY: REJECT */
static void ctcp_reply_dcc_reject(IRC_SERVER_REC *server, const char *data,
				  const char *nick, const char *addr,
				  DCC_REC *chat)
{
        DCC_REC *dcc;
	char *type, *args;

	type = g_strdup(data);
	args = strchr(type, ' ');
        if (args != NULL) *args++ = '\0'; else args = "";

	dcc = dcc_find_request(dcc_str2type(type), nick, args);
	if (dcc != NULL) dcc_close(dcc);

        g_free(type);
}

void dcc_close(DCC_REC *dcc)
{
	signal_emit("dcc closed", 1, dcc);
        dcc_destroy(dcc);
}

/* Reject a DCC request */
void dcc_reject(DCC_REC *dcc, IRC_SERVER_REC *server)
{
	g_return_if_fail(dcc != NULL);

	signal_emit("dcc rejected", 1, dcc);

	if (dcc->server != NULL)
		server = dcc->server;

	if (server != NULL && !dcc_is_connected(dcc)) {
		irc_send_cmdv(server, "NOTICE %s :\001DCC REJECT %s %s\001",
			      dcc->nick, dcc_type2str(dcc->orig_type),
			      dcc->arg);
	}

	dcc_close(dcc);
}

static int dcc_timeout_func(void)
{
	GSList *tmp, *next;
	time_t now;

	now = time(NULL)-settings_get_time("dcc_timeout")/1000;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (dcc->tagread == -1 && now > dcc->created && !IS_DCC_SERVER(dcc)) {
			/* Timed out - don't send DCC REJECT CTCP so CTCP
			   flooders won't affect us and it really doesn't
			   matter that much anyway if the other side doen't
			   get it.. 
			   
			   We don't want dcc servers to time out. */
			dcc_close(dcc);
		}
	}

	return 1;
}

static void event_no_such_nick(IRC_SERVER_REC *server, char *data)
{
	char *params, *nick;
	GSList *tmp, *next;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);

	/* check if we've send any dcc requests to this nick.. */
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (!dcc_is_connected(dcc) && dcc->server == server &&
		    dcc->nick != NULL && g_strcasecmp(dcc->nick, nick) == 0)
			dcc_close(dcc);
	}

	g_free(params);
}

/* SYNTAX: DCC CLOSE <type> <nick> [<file>] */
static void cmd_dcc_close(char *data, IRC_SERVER_REC *server)
{
	GSList *tmp, *next;
	char *typestr, *nick, *arg;
	void *free_arg;
	int found, type;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_GETREST,
			    &typestr, &nick, &arg))
		return;

	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	ascii_strup(typestr);
	type = dcc_str2type(typestr);
	if (type == -1) {
		signal_emit("dcc error unknown type", 1, typestr);
		cmd_params_free(free_arg);
		return;
	}

	found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (dcc->type == type && g_strcasecmp(dcc->nick, nick) == 0 &&
		    (*arg == '\0' || strcmp(dcc->arg, arg) == 0)) {
			dcc_reject(dcc, server);
			found = TRUE;
		}
	}

	if (!found) {
		signal_emit("dcc error close not found", 3,
			    typestr, nick, arg);
	}

	cmd_params_free(free_arg);
}

static void cmd_dcc(const char *data, IRC_SERVER_REC *server, void *item)
{
	command_runsub("dcc", data, server, item);
}

void irc_dcc_init(void)
{
	dcc_conns = NULL;
	dcc_timeouttag = g_timeout_add(1000, (GSourceFunc) dcc_timeout_func, NULL);

	settings_add_str("dcc", "dcc_port", "0");
	settings_add_time("dcc", "dcc_timeout", "5min");
	settings_add_str("dcc", "dcc_own_ip", "");

	signal_add("event connected", (SIGNAL_FUNC) sig_connected);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("server nick changed", (SIGNAL_FUNC) sig_server_nick_changed);
	signal_add("ctcp msg", (SIGNAL_FUNC) ctcp_msg);
	signal_add("ctcp reply", (SIGNAL_FUNC) ctcp_reply);
	signal_add("ctcp msg dcc", (SIGNAL_FUNC) ctcp_msg_dcc);
	signal_add("ctcp reply dcc", (SIGNAL_FUNC) ctcp_reply_dcc);
	signal_add("ctcp reply dcc reject", (SIGNAL_FUNC) ctcp_reply_dcc_reject);
	signal_add("event 401", (SIGNAL_FUNC) event_no_such_nick);
	command_bind("dcc", NULL, (SIGNAL_FUNC) cmd_dcc);
	command_bind("dcc close", NULL, (SIGNAL_FUNC) cmd_dcc_close);

	dcc_chat_init();
	dcc_get_init();
	dcc_send_init();
	dcc_resume_init();
	dcc_autoget_init();
	dcc_server_init();

	settings_check();
	module_register("dcc", "irc");
}

void irc_dcc_deinit(void)
{
	while (dcc_conns != NULL)
		dcc_destroy(dcc_conns->data);

	dcc_chat_deinit();
	dcc_get_deinit();
	dcc_send_deinit();
	dcc_resume_deinit();
	dcc_autoget_deinit();
	dcc_server_deinit();

	signal_remove("event connected", (SIGNAL_FUNC) sig_connected);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("server nick changed", (SIGNAL_FUNC) sig_server_nick_changed);
	signal_remove("ctcp msg", (SIGNAL_FUNC) ctcp_msg);
	signal_remove("ctcp reply", (SIGNAL_FUNC) ctcp_reply);
	signal_remove("ctcp msg dcc", (SIGNAL_FUNC) ctcp_msg_dcc);
	signal_remove("ctcp reply dcc", (SIGNAL_FUNC) ctcp_reply_dcc);
	signal_remove("ctcp reply dcc reject", (SIGNAL_FUNC) ctcp_reply_dcc_reject);
	signal_remove("event 401", (SIGNAL_FUNC) event_no_such_nick);
	command_unbind("dcc", (SIGNAL_FUNC) cmd_dcc);
	command_unbind("dcc close", (SIGNAL_FUNC) cmd_dcc_close);

	g_source_remove(dcc_timeouttag);
}

