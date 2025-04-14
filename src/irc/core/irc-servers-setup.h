#ifndef IRSSI_IRC_CORE_IRC_SERVERS_SETUP_H
#define IRSSI_IRC_CORE_IRC_SERVERS_SETUP_H

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/servers-setup.h>

#define IRC_SERVER_SETUP(server) \
	PROTO_CHECK_CAST(SERVER_SETUP(server), IRC_SERVER_SETUP_REC, \
			 chat_type, "IRC")

#define IS_IRC_SERVER_SETUP(server) \
	(IRC_SERVER_SETUP(server) ? TRUE : FALSE)

enum {
	STARTTLS_DISALLOW = -1, /* */
	STARTTLS_NOTSET = 0,
	STARTTLS_ENABLED = 1
};

typedef struct {
#include <irssi/src/core/server-setup-rec.h>

        /* override the default if > 0 */
	int max_cmds_at_once;
	int cmd_queue_speed;
        int max_query_chans;
	int starttls;
	unsigned int no_cap : 1;
} IRC_SERVER_SETUP_REC;

void irc_servers_setup_init(void);
void irc_servers_setup_deinit(void);

#endif
