#ifndef __BOTNET_USERS_H
#define __BOTNET_USERS_H

void botcmd_user_add(const char *nick);
void botcmd_user_set_flags(USER_REC *user, int flags);
void botcmd_user_set_channel_flags(USER_REC *user, const char *channel, int flags);

void botcmd_user_add_mask(USER_REC *user, const char *mask);
void botcmd_user_set_mask_notflags(USER_REC *user, const char *mask, int not_flags);

void botcmd_user_set_password(USER_REC *user, const char *password);

#endif
