#ifndef __IRC_CHATNETS_H
#define __IRC_CHATNETS_H

#define IS_IRC_CHATNET(chatnet) \
	((chatnet) != NULL && \
	 module_find_id("IRC CHATNET", (chatnet)->chat_type) != -1)

/* returns IRC_CHATNET_REC if it's IRC network, NULL if it isn't */
#define IRC_CHATNET(chatnet) \
	(IS_IRC_CHATNET(chatnet) ? (IRC_CHATNET_REC *) (chatnet) : NULL)

#define IS_IRCNET(ircnet) IS_IRC_CHATNET(ircnet)
#define IRCNET(ircnet) IRC_CHATNET(ircnet)

typedef struct {
#include "chatnet-rec.h"
	int max_cmds_at_once;
	int cmd_queue_speed;

	/* max. number of kicks/msgs/mode/whois per command */
	int max_kicks, max_msgs, max_modes, max_whois;
} IRC_CHATNET_REC;

void ircnet_create(IRC_CHATNET_REC *rec);

#define irc_chatnet_find(name) \
	IRC_CHATNET(chatnet_find(name))
#define ircnet_find(name) irc_chatnet_find(name)

void irc_chatnets_init(void);
void irc_chatnets_deinit(void);

#endif
