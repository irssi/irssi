#ifndef __MODES_H
#define __MODES_H

#include "server.h"
#include "channels.h"

void modes_init(void);
void modes_deinit(void);

/* add `mode' to `old' - return newly allocated mode. */
char *modes_join(const char *old, const char *mode);

void parse_channel_modes(CHANNEL_REC *channel, const char *setby, const char *modestr);

void channel_set_singlemode(IRC_SERVER_REC *server, const char *channel, const char *nicks, const char *mode);
void channel_set_mode(IRC_SERVER_REC *server, const char *channel, const char *mode);

#endif
