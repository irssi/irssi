#ifndef __SERVERS_SETUP_H
#define __SERVERS_SETUP_H

#include "servers.h"

#define IS_SERVER_SETUP(server) \
	((server) != NULL && \
	 module_find_id("SERVER SETUP", (server)->type) != -1)

#define SERVER_SETUP(server) \
	(IS_SERVER_SETUP(server) ? (SERVER_SETUP_REC *) (server) : NULL)

/* servers */
typedef struct {
#include "server-setup-rec.h"
} SERVER_SETUP_REC;

extern GSList *setupservers;

extern IPADDR *source_host_ip; /* Resolved address */
extern int source_host_ok; /* Use source_host_ip .. */

/* Fill reconnection specific information to connection
   from server setup record */
void server_setup_fill_reconn(SERVER_CONNECT_REC *conn,
			      SERVER_SETUP_REC *sserver);

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or chat network */
SERVER_CONNECT_REC *
server_create_conn(const char *dest, int port,
		   const char *password, const char *nick);

/* Find matching server from setup. Try to find record with a same port,
   but fallback to any server with the same address. */
SERVER_SETUP_REC *server_setup_find(const char *address, int port);
/* Find matching server from setup. Ports must match or NULL is returned. */
SERVER_SETUP_REC *server_setup_find_port(const char *address, int port);

void server_setup_add(SERVER_SETUP_REC *rec);
void server_setup_remove(SERVER_SETUP_REC *rec);

void servers_setup_init(void);
void servers_setup_deinit(void);

#endif
