#ifndef __IRC_NICKLIST_H
#define __IRC_NICKLIST_H

#include "nicklist.h"

/* Add new nick to list */
NICK_REC *irc_nicklist_insert(IRC_CHANNEL_REC *channel, const char *nick,
			      int op, int halfop, int voice, int send_massjoin);

/* Remove all "extra" characters from `nick'. Like _nick_ -> nick */
char *irc_nick_strip(const char *nick);

void irc_nicklist_init(void);
void irc_nicklist_deinit(void);

#endif
