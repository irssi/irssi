#ifndef __IRC_SERVERS_SETUP_H
#define __IRC_SERVERS_SETUP_H

#define IS_IRC_SERVER_SETUP(server) \
	((server) != NULL && \
	 module_find_id("IRC SERVER SETUP", (server)->chat_type) != -1)

#define IRC_SERVER_SETUP(server) \
	(IS_IRC_SERVER_SETUP(server) ? \
	 (IRC_SERVER_SETUP_REC *) (server) : NULL)

typedef struct {
#include "server-setup-rec.h"
	int max_cmds_at_once; /* override the default if > 0 */
	int cmd_queue_speed; /* override the default if > 0 */
} IRC_SERVER_SETUP_REC;

void irc_servers_setup_init(void);
void irc_servers_setup_deinit(void);

#endif
