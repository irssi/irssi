#ifndef __CHANNELS_SETUP_H
#define __CHANNELS_SETUP_H

#include "modules.h"

#define CHANNEL_SETUP(server) \
	MODULE_CHECK_CAST(server, CHANNEL_SETUP_REC, type, "CHANNEL SETUP")

#define IS_CHANNEL_SETUP(server) \
	(CHANNEL_SETUP(server) ? TRUE : FALSE)

struct _CHANNEL_SETUP_REC {
#include "channel-setup-rec.h"
};

extern GSList *setupchannels;

void channels_setup_init(void);
void channels_setup_deinit(void);

void channel_setup_create(CHANNEL_SETUP_REC *channel);
void channel_setup_remove(CHANNEL_SETUP_REC *channel);

CHANNEL_SETUP_REC *channel_setup_find(const char *channel,
				      const char *chatnet);

#define channel_chatnet_match(rec, chatnet) \
	((rec) == NULL || (rec)[0] == '\0' || \
	 ((chatnet) != NULL && g_strcasecmp(rec, chatnet) == 0))

#endif
