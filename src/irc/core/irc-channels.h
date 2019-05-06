#ifndef IRSSI_IRC_CORE_IRC_CHANNELS_H
#define IRSSI_IRC_CORE_IRC_CHANNELS_H

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/channels.h>

/* Returns IRC_CHANNEL_REC if it's IRC channel, NULL if it isn't. */
#define IRC_CHANNEL(channel) \
	PROTO_CHECK_CAST(CHANNEL(channel), IRC_CHANNEL_REC, chat_type, "IRC")

#define IS_IRC_CHANNEL(channel) \
	(IRC_CHANNEL(channel) ? TRUE : FALSE)

#define STRUCT_SERVER_REC IRC_SERVER_REC
struct _IRC_CHANNEL_REC {
#include <irssi/src/core/channel-rec.h>

	GSList *banlist; /* list of bans */

	time_t massjoin_start; /* Massjoin start time */
	int massjoins; /* Number of nicks waiting for massjoin signal.. */
	int last_massjoins; /* Massjoins when last checked in timeout function */
};

void irc_channels_init(void);
void irc_channels_deinit(void);

/* Create new IRC channel record */
IRC_CHANNEL_REC *irc_channel_create(IRC_SERVER_REC *server, const char *name,
				    const char *visible_name, int automatic);

#define irc_channel_find(server, name) \
	IRC_CHANNEL(channel_find(SERVER(server), name))

#endif
