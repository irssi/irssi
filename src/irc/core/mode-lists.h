#ifndef __MODE_LISTS_H
#define __MODE_LISTS_H

#include "channels.h"

typedef struct {
	char *ban;
	char *setby;
	time_t time;
} BAN_REC;

BAN_REC *banlist_add(CHANNEL_REC *channel, const char *ban, const char *nick, time_t time);
void banlist_remove(CHANNEL_REC *channel, const char *ban);

BAN_REC *banlist_exception_add(CHANNEL_REC *channel, const char *ban, const char *nick, time_t time);
void banlist_exception_remove(CHANNEL_REC *channel, const char *ban);

void invitelist_add(CHANNEL_REC *channel, const char *mask);
void invitelist_remove(CHANNEL_REC *channel, const char *mask);

void mode_lists_init(void);
void mode_lists_deinit(void);

#endif
