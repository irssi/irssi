#ifndef __SERVER_SETUP_H
#define __SERVER_SETUP_H

#include "irc-server.h"

/* servers */
typedef struct {
	char *server;
	int port;

	char *ircnet;
	char *password;
	int autoconnect;
        int max_cmds_at_once; /* override the default if > 0 */
	int cmd_queue_speed; /* override the default if > 0 */

        char *own_address; /* address to use when connecting this server */
	IPADDR *own_ip; /* resolved own_address or full of zeros */

	time_t last_connect; /* to avoid reconnecting too fast.. */
	int last_failed; /* if last connection attempt failed */
} SETUP_SERVER_REC;

extern GSList *setupservers; /* list of irc servers */

extern IPADDR *source_host_ip; /* Resolved address */
extern gboolean source_host_ok; /* Use source_host_ip .. */

/* Create server connection record. `dest' is required, rest can be NULL.
   `dest' is either a server address or irc network */
IRC_SERVER_CONNECT_REC *
irc_server_create_conn(const char *dest, int port, const char *password, const char *nick);

/* Find matching server from setup. Set port to -1 if you don't care about it */
SETUP_SERVER_REC *server_setup_find(const char *address, int port);

void servers_setup_init(void);
void servers_setup_deinit(void);

#endif
