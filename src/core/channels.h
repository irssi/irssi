#ifndef __CHANNELS_H
#define __CHANNELS_H

#include "modules.h"

/* Returns CHANNEL_REC if it's channel, NULL if it isn't. */
#define CHANNEL(channel) \
	MODULE_CHECK_CAST_MODULE(channel, CHANNEL_REC, type, \
			      "WINDOW ITEM TYPE", "CHANNEL")

#define IS_CHANNEL(channel) \
	(CHANNEL(channel) ? TRUE : FALSE)

#define STRUCT_SERVER_REC SERVER_REC
struct _CHANNEL_REC {
#include "channel-rec.h"
};

extern GSList *channels;

/* Create new channel record */
void channel_init(CHANNEL_REC *channel, SERVER_REC *server, const char *name,
		  const char *visible_name, int automatic);
void channel_destroy(CHANNEL_REC *channel);

/* find channel by name, if `server' is NULL, search from all servers */
CHANNEL_REC *channel_find(SERVER_REC *server, const char *name);

void channel_change_name(CHANNEL_REC *channel, const char *name);
void channel_change_visible_name(CHANNEL_REC *channel, const char *name);

/* Send the auto send command to channel */
void channel_send_autocommands(CHANNEL_REC *channel);

void channels_init(void);
void channels_deinit(void);

#endif
