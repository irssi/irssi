#ifndef IRSSI_IRC_CORE_IRC_CHANNELS_H
#define IRSSI_IRC_CORE_IRC_CHANNELS_H

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/channels.h>

/* Returns IRC_CHANNEL_REC if it's IRC channel, NULL if it isn't. */
#define IRC_CHANNEL(channel) \
	PROTO_CHECK_CAST(CHANNEL(channel), IRC_CHANNEL_REC, chat_type, "IRC")

#define IS_IRC_CHANNEL(channel) \
	(IRC_CHANNEL(channel) ? TRUE : FALSE)

enum {
	CHANNEL_QUERY_MODE,
	CHANNEL_QUERY_WHO,
	CHANNEL_QUERY_BMODE,

	CHANNEL_QUERIES
};

/* arbitrary 3-digit identifiers so we can find our WHOX responses */
#define WHOX_CHANNEL_FULL_ID "743"
#define WHOX_USERACCOUNT_ID "745"

#define CHANNEL_IS_MODE_QUERY(a) ((a) != CHANNEL_QUERY_WHO)

#define STRUCT_SERVER_REC IRC_SERVER_REC
struct _IRC_CHANNEL_REC {
#include <irssi/src/core/channel-rec.h>

	GSList *banlist; /* list of bans */

	time_t massjoin_start; /* Massjoin start time */
	int massjoins; /* Number of nicks waiting for massjoin signal.. */
	int last_massjoins; /* Massjoins when last checked in timeout function */
};

typedef struct _SERVER_QUERY_REC {
	int current_query_type;  /* query type that is currently being asked */
	GSList *current_queries; /* All channels that are currently being queried */

	GSList *queries[CHANNEL_QUERIES]; /* All queries that need to be asked from server */
	GHashTable *accountqueries;       /* Per-nick account queries */
} SERVER_QUERY_REC;

void irc_channels_query_purge_accountquery(IRC_SERVER_REC *server, const char *nick);

void irc_channels_init(void);
void irc_channels_deinit(void);

/* Create new IRC channel record */
IRC_CHANNEL_REC *irc_channel_create(IRC_SERVER_REC *server, const char *name,
				    const char *visible_name, int automatic);

#define irc_channel_find(server, name) \
	IRC_CHANNEL(channel_find(SERVER(server), name))

#endif
