#ifndef __SERVERS_H
#define __SERVERS_H

#include "modules.h"

#ifndef __NETWORK_H
typedef struct _ipaddr IPADDR;
#endif

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

/* all strings should be either NULL or dynamically allocated */
/* address and nick are mandatory, rest are optional */
typedef struct {
#include "server-connect-rec.h"
} SERVER_CONNECT_REC;

#define STRUCT_SERVER_CONNECT_REC SERVER_CONNECT_REC
typedef struct {
#include "server-rec.h"
} SERVER_REC;

extern GSList *servers, *lookup_servers;

void servers_init(void);
void servers_deinit(void);

/* Connect to server */
SERVER_REC *server_connect(SERVER_CONNECT_REC *conn);
/* Disconnect from server */
void server_disconnect(SERVER_REC *server);

SERVER_REC *server_find_tag(const char *tag);
SERVER_REC *server_find_chatnet(const char *chatnet);

int server_start_connect(SERVER_REC *server);
void server_connect_free(SERVER_CONNECT_REC *conn);

#endif
