#ifndef IRSSI_FE_COMMON_IRC_FE_IRC_CHANNELS_H
#define IRSSI_FE_COMMON_IRC_FE_IRC_CHANNELS_H

int fe_channel_is_opchannel(IRC_SERVER_REC *server, const char *target);
const char *fe_channel_skip_prefix(IRC_SERVER_REC *server, const char *target);
char *time_ago(time_t seconds);

void fe_irc_channels_init(void);
void fe_irc_channels_deinit(void);

#endif
