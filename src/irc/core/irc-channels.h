#ifndef __IRC_CHANNELS_H
#define __IRC_CHANNELS_H

#include "channels.h"
#include "irc-servers.h"

#define IS_IRC_CHANNEL(channel) \
	((channel) != NULL && \
	 module_find_id("IRC CHANNEL", \
	                ((IRC_CHANNEL_REC *) (channel))->chat_type) != -1)

/* Returns IRC_CHANNEL_REC if it's IRC channel, NULL if it isn't. */
#define IRC_CHANNEL(channel) \
	(IS_IRC_CHANNEL(channel) ? (IRC_CHANNEL_REC *) (channel) : NULL)

#define STRUCT_SERVER_REC IRC_SERVER_REC
typedef struct {
#include "channel-rec.h"

	GSList *banlist; /* list of bans */
	GSList *ebanlist; /* list of ban exceptions */
	GSList *invitelist; /* invite list */

	time_t massjoin_start; /* Massjoin start time */
	int massjoins; /* Number of nicks waiting for massjoin signal.. */
	int last_massjoins; /* Massjoins when last checked in timeout function */
} IRC_CHANNEL_REC;

void irc_channels_init(void);
void irc_channels_deinit(void);

/* Create new IRC channel record */
IRC_CHANNEL_REC *irc_channel_create(IRC_SERVER_REC *server,
				    const char *name, int automatic);

#define irc_channel_find(server, name) \
	IRC_CHANNEL(channel_find(SERVER(server), name))

/* Join to channels. `data' contains channels and channel keys */
void irc_channels_join(IRC_SERVER_REC *server, const char *data, int automatic);

#endif
