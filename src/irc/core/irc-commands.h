#ifndef __IRC_COMMANDS_H
#define __IRC_COMMANDS_H

/* `optlist' should contain only one key - the server tag.
   returns NULL if there was unknown -option */
IRC_SERVER_REC *irccmd_options_get_server(const char *cmd,
					  GHashTable *optlist,
					  IRC_SERVER_REC *defserver);

#endif
