#ifndef __IRC_COMMANDS_H
#define __IRC_COMMANDS_H

#include "commands.h"

#define command_bind_irc(cmd, section, signal) \
        command_bind_proto(cmd, IRC_PROTOCOL, section, signal)
#define command_bind_irc_first(cmd, section, signal) \
        command_bind_proto_first(cmd, IRC_PROTOCOL, section, signal)
#define command_bind_irc_last(cmd, section, signal) \
        command_bind_proto_last(cmd, IRC_PROTOCOL, section, signal)

/* Simply returns if server isn't for IRC protocol. Prints ERR_NOT_CONNECTED
   error if there's no server or server isn't connected yet */
#define CMD_IRC_SERVER(server) \
	G_STMT_START { \
          if (server != NULL && !IS_IRC_SERVER(server)) \
            return; \
          if (server == NULL || !(server)->connected) \
            cmd_return_error(CMDERR_NOT_CONNECTED); \
	} G_STMT_END

void irc_commands_init(void);
void irc_commands_deinit(void);

#endif
