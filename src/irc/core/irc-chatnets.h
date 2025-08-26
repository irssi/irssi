#ifndef IRSSI_IRC_CORE_IRC_CHATNETS_H
#define IRSSI_IRC_CORE_IRC_CHATNETS_H

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>

/* returns IRC_CHATNET_REC if it's IRC network, NULL if it isn't */
#define IRC_CHATNET(chatnet) \
	PROTO_CHECK_CAST(CHATNET(chatnet), IRC_CHATNET_REC, chat_type, "IRC")

#define IS_IRC_CHATNET(chatnet) \
	(IRC_CHATNET(chatnet) ? TRUE : FALSE)

#define IS_IRCNET(ircnet) IS_IRC_CHATNET(ircnet)
#define IRCNET(ircnet) IRC_CHATNET(ircnet)

struct _IRC_CHATNET_REC {
#include <irssi/src/core/chatnet-rec.h>

	char *usermode;
	char *alternate_nick;

	char *sasl_mechanism;
	char *sasl_username;
	char *sasl_password;

	int max_cmds_at_once;
	int cmd_queue_speed;
	int max_query_chans; /* when syncing, max. number of channels to put in one MODE/WHO command */

	/* max. number of kicks/msgs/mode/whois per command */
	int max_kicks, max_msgs, max_modes, max_whois;
};

void ircnet_create(IRC_CHATNET_REC *rec);

#define irc_chatnet_find(name) \
	IRC_CHATNET(chatnet_find(name))
#define ircnet_find(name) irc_chatnet_find(name)

void irc_chatnets_init(void);
void irc_chatnets_deinit(void);

#endif
