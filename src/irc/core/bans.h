#ifndef __BANS_H
#define __BANS_H

#include "irc-channels.h"

void bans_init(void);
void bans_deinit(void);

char *ban_get_mask(IRC_CHANNEL_REC *channel, const char *nick);

void ban_set_type(const char *type);
void ban_set(IRC_CHANNEL_REC *channel, const char *bans);
void ban_remove(IRC_CHANNEL_REC *channel, const char *ban);

#endif
