#ifndef __SERVERS_H
#define __SERVERS_H

#include "modules.h"

/* Returns SERVER_REC if it's server, NULL if it isn't. */
#define SERVER(server) \
	MODULE_CHECK_CAST(server, SERVER_REC, type, "SERVER")

/* Returns SERVER_CONNECT_REC if it's server connection, NULL if it isn't. */
#define SERVER_CONNECT(conn) \
	MODULE_CHECK_CAST(conn, SERVER_CONNECT_REC, type, "SERVER CONNECT")

#define IS_SERVER(server) \
	(SERVER(server) ? TRUE : FALSE)

#define IS_SERVER_CONNECT(conn) \
	(SERVER_CONNECT(conn) ? TRUE : FALSE)

#define server_ischannel(server, channel) \
        (server)->ischannel(server, channel)

/* all strings should be either NULL or dynamically allocated */
/* address and nick are mandatory, rest are optional */
struct _SERVER_CONNECT_REC {
#include "server-connect-rec.h"
};

#define STRUCT_SERVER_CONNECT_REC SERVER_CONNECT_REC
struct _SERVER_REC {
#include "server-rec.h"
};

#define SEND_TARGET_CHANNEL	0
#define SEND_TARGET_NICK	1

extern GSList *servers, *lookup_servers;

void servers_init(void);
void servers_deinit(void);

/* Disconnect from server */
void server_disconnect(SERVER_REC *server);

void server_ref(SERVER_REC *server);
int server_unref(SERVER_REC *server);

SERVER_REC *server_find_tag(const char *tag);
SERVER_REC *server_find_lookup_tag(const char *tag);
SERVER_REC *server_find_chatnet(const char *chatnet);

/* starts connecting to server */
int server_start_connect(SERVER_REC *server);
void server_connect_ref(SERVER_CONNECT_REC *conn);
void server_connect_unref(SERVER_CONNECT_REC *conn);

SERVER_REC *server_connect(SERVER_CONNECT_REC *conn);

/* initializes server record but doesn't start connecting */
void server_connect_init(SERVER_REC *server);
/* Connection to server finished, fill the rest of the fields */
void server_connect_finished(SERVER_REC *server);
/* connection to server failed */
void server_connect_failed(SERVER_REC *server, const char *msg);

/* Change your nick */
void server_change_nick(SERVER_REC *server, const char *nick);

/* Update own IPv4 and IPv6 records */
void server_connect_own_ip_save(SERVER_CONNECT_REC *conn,
				IPADDR *ip4, IPADDR *ip6);

/* `optlist' should contain only one unknown key - the server tag.
   returns NULL if there was unknown -option */
SERVER_REC *cmd_options_get_server(const char *cmd,
				   GHashTable *optlist,
				   SERVER_REC *defserver);

#endif
