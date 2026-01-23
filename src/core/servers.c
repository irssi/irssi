/*
 server.c : irssi

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
#include <irssi/src/core/commands.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/net-disconnect.h>
#include <irssi/src/core/net-nonblock.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/rawlog.h>
#include <irssi/src/core/refstrings.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-reconnect.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>

GSList *servers, *lookup_servers;

/* connection to server failed */
void server_connect_failed(SERVER_REC *server, const char *msg)
{
	g_return_if_fail(IS_SERVER(server));

	lookup_servers = g_slist_remove(lookup_servers, server);

	signal_emit("server connect failed", 2, server, msg);

	if (server->connect_tag != -1) {
		g_source_remove(server->connect_tag);
		server->connect_tag = -1;
	}
	if (server->connect_cancellable != NULL) {
		g_cancellable_cancel(server->connect_cancellable);
		g_object_unref(server->connect_cancellable);
		server->connect_cancellable = NULL;
	}
	if (server->handle != NULL) {
		net_sendbuffer_destroy(server->handle, TRUE);
		server->handle = NULL;
	}

	server_unref(server);
}

/* generate tag from server's address */
static char *server_create_address_tag(const char *address)
{
	const char *start, *end;

	g_return_val_if_fail(address != NULL, NULL);

	/* try to generate a reasonable server tag */
	if (strchr(address, '.') == NULL) {
		start = end = NULL;
	} else if (g_ascii_strncasecmp(address, "irc", 3) == 0 ||
	    g_ascii_strncasecmp(address, "chat", 4) == 0) {
		/* irc-2.cs.hut.fi -> hut, chat.bt.net -> bt */
		end = strrchr(address, '.');
		start = end-1;
		while (start > address && *start != '.') start--;
	} else {
		/* efnet.cs.hut.fi -> efnet */
		end = strchr(address, '.');
		start = end;
	}

	if (start == end) start = address; else start++;
	if (end == NULL) end = address + strlen(address);

	return g_strndup(start, (int) (end-start));
}

/* create unique tag for server. prefer ircnet's name or
   generate it from server's address */
static char *server_create_tag(SERVER_CONNECT_REC *conn)
{
	GString *str;
	char *tag;
	int num;

	g_return_val_if_fail(IS_SERVER_CONNECT(conn), NULL);

	tag = conn->chatnet != NULL && *conn->chatnet != '\0' ?
		g_strdup(conn->chatnet) :
		server_create_address_tag(conn->address);

	if (conn->tag != NULL && server_find_tag(conn->tag) == NULL &&
            server_find_lookup_tag(conn->tag) == NULL &&
	    strncmp(conn->tag, tag, strlen(tag)) == 0) {
		/* use the existing tag if it begins with the same ID -
		   this is useful when you have several connections to
		   same server and you want to keep the same tags with
		   the servers (or it would cause problems when rejoining
		   /LAYOUT SAVEd channels). */
		g_free(tag);
		return g_strdup(conn->tag);
	}


	/* then just append numbers after tag until unused is found.. */
	str = g_string_new(tag);

	num = 2;
	while (server_find_tag(str->str) != NULL ||
	       server_find_lookup_tag(str->str) != NULL) {
		g_string_printf(str, "%s%d", tag, num);
		num++;
	}
	g_free(tag);

	tag = g_string_free(str, FALSE);
	return tag;
}

/* Connection to server finished, fill the rest of the fields */
void server_connect_finished(SERVER_REC *server)
{
	server->connect_time = time(NULL);

	servers = g_slist_append(servers, server);
	signal_emit("server connected", 1, server);
}

static void server_connect_callback_init_channel(SERVER_REC *server, GIOChannel *channel)
{
	int error;

	g_return_if_fail(IS_SERVER(server));

	error = net_geterror_channel(channel);
	if (error != 0) {
		server->connection_lost = TRUE;
		server->connrec->last_failed = server->connrec->last_connected;
		server_connect_failed(server, g_strerror(error));
		return;
	}

	lookup_servers = g_slist_remove(lookup_servers, server);
	g_source_remove(server->connect_tag);
	server->connect_tag = -1;

	server_connect_finished(server);
}

static void server_connect_callback_init_ssl_channel(SERVER_REC *server, GIOChannel *channel)
{
	int error;

	g_return_if_fail(IS_SERVER(server));

	error = irssi_ssl_handshake_channel(channel);
	if (error == -1) {
		server->connection_lost = TRUE;
		server->connrec->last_failed = server->connrec->last_connected;
		server_connect_failed(server, NULL);
		return;
	}
	if (error & 1) {
		if (server->connect_tag != -1)
			g_source_remove(server->connect_tag);
		server->connect_tag =
		    i_input_add(channel, error == 1 ? I_INPUT_READ : I_INPUT_WRITE,
		                (GInputFunction) server_connect_callback_init_ssl_channel, server);
		return;
	}

	lookup_servers = g_slist_remove(lookup_servers, server);
	if (server->connect_tag != -1) {
		g_source_remove(server->connect_tag);
		server->connect_tag = -1;
	}

	server_connect_finished(server);
}

static void server_real_connect(SERVER_REC *server, IPADDR *ip, const char *unix_socket,
                                const char *host)
{
	GIOChannel *channel;
	const char *errmsg;
	char *errmsg2;
	IPADDR *own_ip = NULL;
	char ipaddr[MAX_IP_LEN];
	int port = 0;

	g_return_if_fail(ip != NULL || unix_socket != NULL || host != NULL);

	if (ip != NULL) {
		server->connrec->chosen_family = ip->family;
		net_ip2host(ip, ipaddr);
		server->connrec->ipaddr = g_strdup(ipaddr);
	}

	signal_emit("server connecting", 3, server, ip, ip != NULL ? ipaddr : host);

	if (server->connrec->no_connect)
		return;

	if (ip != NULL) {
		own_ip = IPADDR_IS_V6(ip) ? server->connrec->own_ip6 : server->connrec->own_ip4;
		port = server->connrec->proxy != NULL ?
			server->connrec->proxy_port : server->connrec->port;
		channel = net_connect_ip_channel(ip, port, own_ip);
	} else {
		channel = net_connect_unix_channel(unix_socket);
	}

	if (server->connrec->use_tls && channel != NULL) {
		server->handle = net_sendbuffer_create_channel(channel, 0);
		channel = net_start_ssl_channel(server);
		if (channel == NULL) {
			net_sendbuffer_destroy(server->handle, TRUE);
			server->handle = NULL;
		} else {
			server->handle->channel = channel;
		}
	}

	if (channel == NULL) {
		/* failed */
		errmsg = g_strerror(errno);
		errmsg2 = NULL;
		if (errno == EADDRNOTAVAIL) {
			if (own_ip != NULL) {
				/* show the IP which is causing the error */
				net_ip2host(own_ip, ipaddr);
				errmsg2 = g_strconcat(errmsg, ": ", ipaddr, NULL);
			}
			server->no_reconnect = TRUE;
		}
		if (server->connrec->use_tls && errno == ENOSYS)
			server->no_reconnect = TRUE;

		server->connection_lost = TRUE;
		if (ip != NULL) {
			server->connrec->last_failed = server->connrec->last_connected;
		}
		server_connect_failed(server, errmsg2 ? errmsg2 : errmsg);
		g_free(errmsg2);
	} else {
		server->connrec->last_failed = 0;
		if (!server->connrec->use_tls)
			server->handle = net_sendbuffer_create_channel(channel, 0);
		if (server->connrec->use_tls)
			server_connect_callback_init_ssl_channel(server, channel);
		else
			server->connect_tag = i_input_add(
			    channel, I_INPUT_WRITE | I_INPUT_READ,
			    (GInputFunction) server_connect_callback_init_channel, server);
	}
}

static int server_start_connect_resolve(SERVER_REC *server);

static void server_connect_use_resolved(SERVER_REC *server)
{
	IPADDR *ip;
	const char *errormsg;
	RESOLVED_IP_REC *iprec = server->connrec->resolved_host;

	if (iprec->error != NULL) {
		/* error */
		ip = NULL;
	} else {
		GList *curr;
		int i;

		curr = iprec->ailist;
		i = 0;
		while (i < server->connrec->last_failed) {
			if (curr != NULL) {
				curr = curr->next;
				i++;
			}
			/* curr is different now */
			if (curr == NULL) {
				resolved_ip_unref(server->connrec->resolved_host);
				server->connrec->resolved_host = NULL;
				server->connrec->last_failed = 0;
				/* retry resolve */
				server_start_connect_resolve(server);
				return;
			}
		}
		if (curr != NULL) {
			GInetAddress *addr;
			addr = curr->data;
			server->connrec->last_connected = i + 1;
			ip = g_new0(IPADDR, 1);
			ip->family = g_inet_address_get_family(addr);
			memcpy(&ip->ip, g_inet_address_to_bytes(addr), sizeof(ip->ip));
		} else {
			ip = NULL;
		}
	}

	if (ip != NULL) {
		/* host lookup ok */
		server_real_connect(server, ip, NULL, NULL);
		errormsg = NULL;
	} else {
		if (iprec->error->code == G_RESOLVER_ERROR_NOT_FOUND) {
			/* IP wasn't found for the host, don't try to
			   reconnect back to this server */
			server->dns_error = TRUE;
		}

		errormsg = iprec->error->message;
		if (errormsg == NULL)
			errormsg = "Host lookup failed";

		server->connection_lost = TRUE;
		/* clear the error in resolved_host */
		server->connrec->resolved_host = NULL;
		server_connect_failed(server, errormsg);

		resolved_ip_unref(iprec);
	}

	g_free(ip);
}

static void server_connect_callback_resolved(RESOLVED_IP_REC *iprec, SERVER_REC *server)
{
	if (server->connect_cancellable != NULL) {
		g_object_unref(server->connect_cancellable);
		server->connect_cancellable = NULL;
	}

	if (server->connrec->resolved_host != NULL) {
		resolved_ip_unref(server->connrec->resolved_host);
	}
	server->connrec->resolved_host = iprec;

	if (iprec->error == NULL && iprec->ailist == NULL) {
		server->connection_lost = TRUE;
		server->dns_error = TRUE;
		server_connect_failed(server, "Host lookup failed");
	} else {
		server_connect_use_resolved(server);
	}
}

static int server_start_connect_resolve(SERVER_REC *server)
{
	const char *connect_address;
	GResolverNameLookupFlags net_gethostbyname_flags;

	connect_address =
	    server->connrec->proxy != NULL ? server->connrec->proxy : server->connrec->address;
	net_gethostbyname_flags = G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT;
	if (server->connrec->family == AF_INET) {
		net_gethostbyname_flags = G_RESOLVER_NAME_LOOKUP_FLAGS_IPV4_ONLY;
	} else if (server->connrec->family == AF_INET6) {
		net_gethostbyname_flags = G_RESOLVER_NAME_LOOKUP_FLAGS_IPV6_ONLY;
	}
	if (server->connrec->resolved_host == NULL) {
		server->connect_cancellable = net_gethostbyname_nonblock(
		    connect_address, net_gethostbyname_flags,
		    (NetGethostbynameContinuationFunc) server_connect_callback_resolved, server);
		return FALSE;
	} else {
		return TRUE;
	}
}

SERVER_REC *server_connect(SERVER_CONNECT_REC *conn)
{
	CHAT_PROTOCOL_REC *proto;
	SERVER_REC *server;

	proto = CHAT_PROTOCOL(conn);
	server = proto->server_init_connect(conn);
	proto->server_connect(server);

	return server;
}

/* initializes server record but doesn't start connecting */
void server_connect_init(SERVER_REC *server)
{
	const char *str;

	g_return_if_fail(server != NULL);

	MODULE_DATA_INIT(server);
	server->type = module_get_uniq_id("SERVER", 0);
	server_ref(server);
	server->current_incoming_meta =
	    g_hash_table_new_full(g_str_hash, (GEqualFunc) g_str_equal,
	                          (GDestroyNotify) i_refstr_release, (GDestroyNotify) g_free);

	server->nick = g_strdup(server->connrec->nick);
	if (server->connrec->username == NULL || *server->connrec->username == '\0') {
		g_free_not_null(server->connrec->username);

		str = g_get_user_name();
		if (*str == '\0') str = "unknown";
		server->connrec->username = g_strdup(str);
	}
	if (server->connrec->realname == NULL || *server->connrec->realname == '\0') {
		g_free_not_null(server->connrec->realname);

		str = g_get_real_name();
		if (*str == '\0') str = server->connrec->username;
		server->connrec->realname = g_strdup(str);
	}

	server->tag = server_create_tag(server->connrec);
	server->connect_tag = -1;
}

/* starts connecting to server */
int server_start_connect(SERVER_REC *server)
{
	g_return_val_if_fail(server != NULL, FALSE);
	if (!server->connrec->unix_socket && server->connrec->port <= 0)
		return FALSE;

	server->rawlog = rawlog_create();

	if (server->connrec->connect_channel != NULL) {
		/* already connected */
		GIOChannel *channel = server->connrec->connect_channel;

		server->connrec->connect_channel = NULL;
		server->handle = net_sendbuffer_create_channel(channel, 0);
		server_connect_finished(server);
	} else if (server->connrec->unix_socket) {
		/* connect with unix socket */
		server_real_connect(server, NULL, server->connrec->address, NULL);
	} else {
		int already_resolved;
		/* resolve host name */
		already_resolved = server_start_connect_resolve(server);

		server->connect_time = time(NULL);
		lookup_servers = g_slist_append(lookup_servers, server);

		signal_emit("server looking", 1, server);
		if (already_resolved) {
			server_connect_use_resolved(server);
		}
	}
	return TRUE;
}

static int server_remove_channels(SERVER_REC *server)
{
	GSList *tmp, *next;
	int found;

	g_return_val_if_fail(server != NULL, FALSE);

	found = FALSE;
	for (tmp = server->channels; tmp != NULL; tmp = next) {
		CHANNEL_REC *channel = tmp->data;

		next = tmp->next;
		channel_destroy(channel);
		found = TRUE;
	}

	while (server->queries != NULL)
		query_change_server(server->queries->data, NULL);

	g_slist_free(server->channels);
	g_slist_free(server->queries);

	return found;
}

void server_disconnect(SERVER_REC *server)
{
	g_return_if_fail(IS_SERVER(server));

	if (server->disconnected)
		return;

	if (server->connect_tag != -1) {
		/* still connecting to server.. */
		server_connect_failed(server, NULL);
		return;
	} else if (server->connect_cancellable != NULL) {
		server_connect_failed(server, NULL);
		return;
	}

	servers = g_slist_remove(servers, server);

	server->disconnected = TRUE;
	signal_emit("server disconnected", 1, server);

	/* we used to destroy the handle here but it may be still in
	   use during signal processing, so destroy it on unref
	   instead */

	if (server->readtag > 0) {
		g_source_remove(server->readtag);
		server->readtag = -1;
	}

	server_unref(server);
}

void server_ref(SERVER_REC *server)
{
	g_return_if_fail(IS_SERVER(server));

	server->refcount++;
}

int server_unref(SERVER_REC *server)
{
	int chans;

	g_return_val_if_fail(IS_SERVER(server), FALSE);

	if (--server->refcount > 0)
		return TRUE;

	if (g_slist_find(servers, server) != NULL) {
		g_warning("Non-referenced server wasn't disconnected");
		server_disconnect(server);
		return TRUE;
	}

	/* close all channels */
	chans = server_remove_channels(server);

	/* since module initialisation uses server connected, only let
	   them know that the object got destroyed if the server was
	   disconnected */
	if (server->disconnected) {
		signal_emit("server destroyed", 1, server);
	}

	if (server->handle != NULL) {
		if (!chans || server->connection_lost)
			net_sendbuffer_destroy(server->handle, TRUE);
		else {
			/* we were on some channels, try to let the server
			   disconnect so that our quit message is guaranteed
			   to get displayed */
			net_disconnect_later(server->handle);
			net_sendbuffer_destroy(server->handle, FALSE);
		}
		server->handle = NULL;
	}

        MODULE_DATA_DEINIT(server);
	server_connect_unref(server->connrec);
	if (server->rawlog != NULL) rawlog_destroy(server->rawlog);
	g_free(server->version);
	g_free(server->away_reason);
	g_free(server->nick);
	g_free(server->tag);
	g_hash_table_destroy(server->current_incoming_meta);

	server->type = 0;
	g_free(server);
        return FALSE;
}

SERVER_REC *server_find_tag(const char *tag)
{
	GSList *tmp;

	g_return_val_if_fail(tag != NULL, NULL);
	if (*tag == '\0') return NULL;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (g_ascii_strcasecmp(server->tag, tag) == 0)
			return server;
	}

	return NULL;
}

SERVER_REC *server_find_lookup_tag(const char *tag)
{
	GSList *tmp;

	g_return_val_if_fail(tag != NULL, NULL);
	if (*tag == '\0') return NULL;

	for (tmp = lookup_servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (g_ascii_strcasecmp(server->tag, tag) == 0)
			return server;
	}

	return NULL;
}

SERVER_REC *server_find_chatnet(const char *chatnet)
{
	GSList *tmp;

	g_return_val_if_fail(chatnet != NULL, NULL);
	if (*chatnet == '\0') return NULL;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (server->connrec->chatnet != NULL &&
		    g_ascii_strcasecmp(server->connrec->chatnet, chatnet) == 0)
			return server;
	}

	return NULL;
}

void server_connect_ref(SERVER_CONNECT_REC *conn)
{
        conn->refcount++;
}

void server_connect_unref(SERVER_CONNECT_REC *conn)
{
	g_return_if_fail(IS_SERVER_CONNECT(conn));

	if (--conn->refcount > 0)
		return;
	if (conn->refcount < 0) {
		g_warning("Connection '%s' refcount = %d",
			  conn->tag, conn->refcount);
	}

        CHAT_PROTOCOL(conn)->destroy_server_connect(conn);

	if (conn->connect_channel != NULL)
		net_disconnect_channel(conn->connect_channel);

	g_free_not_null(conn->proxy);
	g_free_not_null(conn->proxy_string);
	g_free_not_null(conn->proxy_string_after);
	g_free_not_null(conn->proxy_password);

	g_free_not_null(conn->ipaddr);
	g_free_not_null(conn->tag);
	g_free_not_null(conn->address);
	g_free_not_null(conn->chatnet);

	g_free_not_null(conn->own_ip4);
	g_free_not_null(conn->own_ip6);

	if (conn->resolved_host != NULL) {
		resolved_ip_unref(conn->resolved_host);
	}

	g_free_not_null(conn->password);
	g_free_not_null(conn->nick);
	g_free_not_null(conn->username);
	g_free_not_null(conn->realname);

	g_free_not_null(conn->tls_cert);
	g_free_not_null(conn->tls_pkey);
	g_free_not_null(conn->tls_pass);
	g_free_not_null(conn->tls_cafile);
	g_free_not_null(conn->tls_capath);
	g_free_not_null(conn->tls_ciphers);
	g_free_not_null(conn->tls_pinned_cert);
	g_free_not_null(conn->tls_pinned_pubkey);

	g_free_not_null(conn->channels);
	g_free_not_null(conn->away_reason);

	conn->type = 0;
	g_free(conn);
}

void server_change_nick(SERVER_REC *server, const char *nick)
{
	g_free(server->nick);
	server->nick = g_strdup(nick);

	signal_emit("server nick changed", 1, server);
}

void server_meta_stash(SERVER_REC *server, const char *meta_key, const char *meta_value)
{
	g_hash_table_replace(server->current_incoming_meta, i_refstr_intern(meta_key),
	                     g_strdup(meta_value));
}

const char *server_meta_stash_find(SERVER_REC *server, const char *meta_key)
{
	return g_hash_table_lookup(server->current_incoming_meta, meta_key);
}

void server_meta_clear_all(SERVER_REC *server)
{
	g_hash_table_remove_all(server->current_incoming_meta);
}

/* Update own IPv4 and IPv6 records */
void server_connect_own_ip_save(SERVER_CONNECT_REC *conn,
				IPADDR *ip4, IPADDR *ip6)
{
	if (ip4 == NULL || ip4->family == 0)
		g_free_and_null(conn->own_ip4);
	if (ip6 == NULL || ip6->family == 0)
		g_free_and_null(conn->own_ip6);

	if (ip4 != NULL && ip4->family != 0) {
		/* IPv4 address was found */
		if (conn->own_ip4 == NULL)
			conn->own_ip4 = g_new0(IPADDR, 1);
		memcpy(conn->own_ip4, ip4, sizeof(IPADDR));
	}

	if (ip6 != NULL && ip6->family != 0) {
		/* IPv6 address was found */
		if (conn->own_ip6 == NULL)
			conn->own_ip6 = g_new0(IPADDR, 1);
		memcpy(conn->own_ip6, ip6, sizeof(IPADDR));
	}
}

/* `optlist' should contain only one unknown key - the server tag.
   returns NULL if there was unknown -option */
SERVER_REC *cmd_options_get_server(const char *cmd,
				   GHashTable *optlist,
				   SERVER_REC *defserver)
{
	SERVER_REC *server;
	GList *list;

	/* get all the options, then remove the known ones. there should
	   be only one left - the server tag. */
	list = optlist_remove_known(cmd, optlist);
	if (list == NULL)
		return defserver;

	server = server_find_tag(list->data);
	if (server == NULL || list->next != NULL) {
		/* unknown option (not server tag) */
		signal_emit("error command", 2,
			    GINT_TO_POINTER(CMDERR_OPTION_UNKNOWN),
			    server == NULL ? list->data : list->next->data);
		signal_stop();

		server = NULL;
	}

	g_list_free(list);
	return server;
}

static void disconnect_servers(GSList *servers, int chat_type)
{
	GSList *tmp, *next;

	for (tmp = servers; tmp != NULL; tmp = next) {
		SERVER_REC *rec = tmp->data;

                next = tmp->next;
                if (rec->chat_type == chat_type)
			server_disconnect(rec);
	}
}

static void sig_chat_protocol_deinit(CHAT_PROTOCOL_REC *proto)
{
        disconnect_servers(servers, proto->id);
        disconnect_servers(lookup_servers, proto->id);
}

void servers_init(void)
{
	lookup_servers = servers = NULL;

	signal_add("chat protocol deinit", (SIGNAL_FUNC) sig_chat_protocol_deinit);

	servers_reconnect_init();
	servers_setup_init();
}

void servers_deinit(void)
{
	signal_remove("chat protocol deinit", (SIGNAL_FUNC) sig_chat_protocol_deinit);

	servers_setup_deinit();
	servers_reconnect_deinit();

	module_uniq_destroy("SERVER");
	module_uniq_destroy("SERVER CONNECT");
}
