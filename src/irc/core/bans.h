#ifndef __BANS_H
#define __BANS_H

void bans_init(void);
void bans_deinit(void);

/* if ban_type is <= 0, use the default */
char *ban_get_mask(IRC_CHANNEL_REC *channel, const char *nick, int ban_type);
char *ban_get_masks(IRC_CHANNEL_REC *channel, const char *nicks, int ban_type);

void ban_set(IRC_CHANNEL_REC *channel, const char *bans, int ban_type);
void ban_remove(IRC_CHANNEL_REC *channel, const char *bans);

#endif
