#ifndef __IRC_SERVERS_SETUP_H
#define __IRC_SERVERS_SETUP_H

#include "chat-protocols.h"
#include "servers-setup.h"

#define IRC_SERVER_SETUP(server) \
	PROTO_CHECK_CAST(SERVER_SETUP(server), IRC_SERVER_SETUP_REC, \
			 chat_type, "IRC")

#define IS_IRC_SERVER_SETUP(server) \
	(IRC_SERVER_SETUP(server) ? TRUE : FALSE)

typedef struct {
#include "server-setup-rec.h"
	int max_cmds_at_once; /* override the default if > 0 */
	int cmd_queue_speed; /* override the default if > 0 */
} IRC_SERVER_SETUP_REC;

void irc_servers_setup_init(void);
void irc_servers_setup_deinit(void);

#endif
