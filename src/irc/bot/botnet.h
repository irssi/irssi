#ifndef __BOT_BOTNET_H
#define __BOT_BOTNET_H

#include "nicklist.h"

#define DEFAULT_BOTNET_PORT 2255
#define DEFAULT_BOTNET_PRIORITY 5

typedef struct _botnet_rec BOTNET_REC;

typedef struct {
	char *name;
	GSList *nicks; /* NICK_RECs */
	unsigned int chanop:1;

	GSList *banlist;
	GSList *ebanlist;
	GSList *invitelist;

	char *mode;
	int limit;
	char *key;
} BOT_CHANNEL_REC;

typedef struct {
        char *tag; /* same as server->tag */
	char *ircnet;
        char *server;
	char *nick;

	GSList *channels;
} BOT_IRCNET_REC;

typedef struct {
	BOTNET_REC *botnet;
	void *link; /* NULL, BOT_UPLINK_REC or BOT_DOWNLINK_REC */

	unsigned int uplink:1; /* this is our uplink */
	unsigned int pass_ok:1; /* downlink's password was ok */
	unsigned int connected:1; /* bot is in this botnet now */
	unsigned int disconnect:1; /* just disconnecting this bot.. */
	unsigned int master:1; /* this bot is the bot network's current master */

	char *nick; /* bot's unique nick in botnet */
	int priority;

	GIOChannel *handle;
	int read_tag;
	LINEBUF_REC *buffer;

	int file_handle; /* if bot is sending a file to us */

	GSList *ircnets;
} BOT_REC;

typedef struct {
	BOTNET_REC *botnet;

	char *host;
	int port;
	char *password;

	time_t last_connect;
} BOT_UPLINK_REC;

typedef struct {
	BOTNET_REC *botnet;

	GSList *valid_addrs; /* IP/host masks where this bot is allowed to connect */
	char *password;
} BOT_DOWNLINK_REC;

struct _botnet_rec {
	unsigned int connected:1;
	unsigned int autoconnect:1;
	unsigned int reconnect:1;

	char *name; /* botnet name */
	char *nick; /* our nick in botnet */
	int priority; /* our priority in botnet */

	char *addr; /* in what address we should listen, NULL = all */
	int port; /* what port we should listen, 0 = default, -1 = don't listen */

	GIOChannel *listen_handle;
	int listen_tag;

	GSList *uplinks;
	GSList *downlinks;

	GNode *bots;
	BOT_REC *uplink; /* our current uplink */
	BOT_REC *master; /* link to current master */
};

extern GSList *botnets;

void bot_send_cmd(BOT_REC *bot, const char *data);
void bot_send_cmdv(BOT_REC *bot, const char *format, ...);

/* broadcast a message to everyone in bot network, except for `except_bot'
   if it's not NULL. If botnet is NULL, the message is sent to all botnets. */
void botnet_broadcast(BOTNET_REC *botnet, BOT_REC *except_bot,
		      const char *source, const char *data);

void botnet_send_cmd(BOTNET_REC *botnet, const char *source,
		     const char *target, const char *data);

int botnet_send_file(BOTNET_REC *botnet, const char *target, const char *fname);

BOT_REC *botnet_find_master(BOTNET_REC *botnet, BOT_REC *old_master);
void botnet_set_master(BOTNET_REC *botnet, BOT_REC *bot);

BOTNET_REC *botnet_find(const char *name);
GNode *bot_find_nick(BOTNET_REC *botnet, const char *nick);
/* Return the bot who we should send the message if we wanted `nick' to get it. */
GNode *bot_find_path(BOTNET_REC *botnet, const char *nick);

BOT_DOWNLINK_REC *bot_downlink_find(BOTNET_REC *botnet, IPADDR *ip, const char *host);

void bot_nick_destroy(BOT_CHANNEL_REC *rec, NICK_REC *nick);
void bot_channel_destroy(BOT_IRCNET_REC *ircnet, BOT_CHANNEL_REC *rec);
void bot_ircnet_destroy(BOT_REC *bot, BOT_IRCNET_REC *rec);

void bot_disconnect(BOT_REC *bot);
void bot_destroy(BOT_REC *bot);

void bot_downlink_destroy(BOT_DOWNLINK_REC *rec);
void bot_uplink_destroy(BOT_UPLINK_REC *rec);

void botnet_connect(BOTNET_REC *botnet);
void botnet_disconnect(BOTNET_REC *botnet);

#endif
