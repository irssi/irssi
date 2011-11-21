#ifndef __IRC_NICKLIST_H
#define __IRC_NICKLIST_H

#include "nicklist.h"

/* Add new nick to list */
NICK_REC *irc_nicklist_insert(IRC_CHANNEL_REC *channel, const char *nick,
			      int op, int halfop, int voice, int send_massjoin,
			      const char *prefixes);

/* Remove all "extra" characters from `nick'. Like _nick_ -> nick */
char *irc_nick_strip(const char *nick);

int irc_nickcmp_rfc1459(const char *, const char *);
int irc_nickcmp_ascii(const char *, const char *);

void irc_nicklist_init(void);
void irc_nicklist_deinit(void);

#define to_rfc1459(x) ((x) >= 65 && (x) <= 94 ? (x) + 32 : (x))
#define to_ascii(x) ((x) >= 65 && (x) <= 90 ? (x) + 32 : (x))

#endif
