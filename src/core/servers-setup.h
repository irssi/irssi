#ifndef IRSSI_CORE_SERVERS_SETUP_H
#define IRSSI_CORE_SERVERS_SETUP_H

#include <irssi/src/core/modules.h>

#define SERVER_SETUP(server) \
	MODULE_CHECK_CAST(server, SERVER_SETUP_REC, type, "SERVER SETUP")

#define IS_SERVER_SETUP(server) \
	(SERVER_SETUP(server) ? TRUE : FALSE)

/* servers */
struct _SERVER_SETUP_REC {
#include <irssi/src/core/server-setup-rec.h>
};

extern GSList *setupservers;

extern IPADDR *source_host_ip4, *source_host_ip6; /* Resolved address */
extern int source_host_ok; /* Use source_host_ip .. */

/* Fill reconnection specific information to connection
   from server setup record */
void server_setup_fill_reconn(SERVER_CONNECT_REC *conn,
			      SERVER_SETUP_REC *sserver);

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or chat network */
SERVER_CONNECT_REC *
server_create_conn(int chat_type, const char *dest, int port,
		   const char *chatnet, const char *password,
		   const char *nick);

SERVER_CONNECT_REC *server_create_conn_opt(int chat_type, const char *dest, int port,
                                           const char *chatnet, const char *password,
                                           const char *nick, GHashTable *optlist);

/* Find matching server from setup. Try to find record with a same port,
   but fallback to any server with the same address. */
SERVER_SETUP_REC *server_setup_find(const char *address, int port,
				    const char *chatnet);

void server_setup_add(SERVER_SETUP_REC *rec);
void server_setup_modify(SERVER_SETUP_REC *rec, int old_port, const char *old_chatnet);
void server_setup_remove(SERVER_SETUP_REC *rec);

/* Remove servers attached to chatne */
void server_setup_remove_chatnet(const char *chatnet);

void servers_setup_init(void);
void servers_setup_deinit(void);

#endif
