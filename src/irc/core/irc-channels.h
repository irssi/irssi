#ifndef __IRC_CHANNELS_H
#define __IRC_CHANNELS_H

#include "chat-protocols.h"
#include "channels.h"
#include "irc-servers.h"

/* Returns IRC_CHANNEL_REC if it's IRC channel, NULL if it isn't. */
#define IRC_CHANNEL(channel) \
	PROTO_CHECK_CAST(CHANNEL(channel), IRC_CHANNEL_REC, chat_type, "IRC")

#define IS_IRC_CHANNEL(channel) \
	(IRC_CHANNEL(channel) ? TRUE : FALSE)

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
void irc_channels_join(IRC_SERVER_REC *server,
		       const char *data, int automatic);

#endif
