#ifndef __SERVER_SETUP_H
#define __SERVER_SETUP_H

#include "irc-server.h"

/* servers */
typedef struct {
	char *address;
	int port;

	char *ircnet;
	char *password;
	int autoconnect;
        int max_cmds_at_once; /* override the default if > 0 */
	int cmd_queue_speed; /* override the default if > 0 */

        char *own_host; /* address to use when connecting this server */
	IPADDR *own_ip; /* resolved own_address if not NULL */

	time_t last_connect; /* to avoid reconnecting too fast.. */
	int last_failed:1; /* if last connection attempt failed */
	int banned:1; /* if we're banned from this server */
} SETUP_SERVER_REC;

extern GSList *setupservers; /* list of irc servers */

extern IPADDR *source_host_ip; /* Resolved address */
extern gboolean source_host_ok; /* Use source_host_ip .. */

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or irc network */
IRC_SERVER_CONNECT_REC *
irc_server_create_conn(const char *dest, int port, const char *password, const char *nick);

/* Fill information to connection from server setup record */
void server_setup_fill_conn(IRC_SERVER_CONNECT_REC *conn, SETUP_SERVER_REC *sserver);

void server_setup_add(SETUP_SERVER_REC *rec);
void server_setup_remove(SETUP_SERVER_REC *rec);

/* Find matching server from setup. Set port to -1 if you don't care about it */
SETUP_SERVER_REC *server_setup_find(const char *address, int port);

void servers_setup_init(void);
void servers_setup_deinit(void);

#endif
