#ifndef __CHANNELS_H
#define __CHANNELS_H

#include "servers.h"

/* Returns CHANNEL_REC if it's channel, NULL if it isn't. */
#define CHANNEL(channel) \
	MODULE_CHECK_CAST(channel, CHANNEL_REC, type, "CHANNEL")

#define IS_CHANNEL(channel) \
	(CHANNEL(channel) ? TRUE : FALSE)

#define STRUCT_SERVER_REC SERVER_REC
typedef struct {
#include "channel-rec.h"
} CHANNEL_REC;

extern GSList *channels;

void channels_init(void);
void channels_deinit(void);

/* Create new channel record */
void channel_init(CHANNEL_REC *channel, int automatic);
void channel_destroy(CHANNEL_REC *channel);

/* find channel by name, if `server' is NULL, search from all servers */
CHANNEL_REC *channel_find(SERVER_REC *server, const char *name);

#endif
