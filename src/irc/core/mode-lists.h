#ifndef __MODE_LISTS_H
#define __MODE_LISTS_H

typedef struct {
	char *ban;
	char *setby;
	time_t time;
} BAN_REC;

BAN_REC *banlist_find(GSList *list, const char *ban);

BAN_REC *banlist_add(IRC_CHANNEL_REC *channel, const char *ban, const char *nick, time_t time);
void banlist_remove(IRC_CHANNEL_REC *channel, const char *ban, const char *nick);

BAN_REC *banlist_exception_add(IRC_CHANNEL_REC *channel, const char *ban, const char *nick, time_t time);
void banlist_exception_remove(IRC_CHANNEL_REC *channel, const char *ban);

void invitelist_add(IRC_CHANNEL_REC *channel, const char *mask);
void invitelist_remove(IRC_CHANNEL_REC *channel, const char *mask);

void mode_lists_init(void);
void mode_lists_deinit(void);

#endif
