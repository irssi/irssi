#ifndef __BANS_H
#define __BANS_H

#include "channels.h"

void bans_init(void);
void bans_deinit(void);

char *ban_get_mask(CHANNEL_REC *channel, const char *nick);

void ban_set_type(const char *type);
void ban_set(CHANNEL_REC *channel, const char *bans);
void ban_remove(CHANNEL_REC *channel, const char *ban);

#endif
