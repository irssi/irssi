#ifndef __IRC_NICKLIST_H
#define __IRC_NICKLIST_H

#include "nicklist.h"

void irc_nicklist_init(void);
void irc_nicklist_deinit(void);

/* Remove all "extra" characters from `nick'. Like _nick_ -> nick */
char *irc_nick_strip(const char *nick);

#endif
