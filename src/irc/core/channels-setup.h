#ifndef __CHANNELS_SETUP_H
#define __CHANNELS_SETUP_H

typedef struct {
	int autojoin;

	char *name;
	char *ircnet;
	char *password;

	char *botmasks;
	char *autosendcmd;

	char *background;
	char *font;
} SETUP_CHANNEL_REC;

extern GSList *setupchannels;

void channels_setup_init(void);
void channels_setup_deinit(void);

void channels_setup_destroy(SETUP_CHANNEL_REC *channel);

SETUP_CHANNEL_REC *channels_setup_find(const char *channel, IRC_SERVER_REC *server);

#endif
