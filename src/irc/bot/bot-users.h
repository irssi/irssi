#ifndef __BOT_USERS_H
#define __BOT_USERS_H

#define USER_OP         0x0001
#define USER_AUTO_OP    0x0002
#define USER_AUTO_VOICE 0x0004
#define USER_MASTER     0x0008

#define USER_FLAG_COUNT 4

/* Channel specific flags */
typedef struct {
	char *channel;
	int flags;
	NICK_REC *nickrec; /* Nick record in channel,
	FIXME: User can be in channel with multiple nicks too! */
} USER_CHAN_REC;

typedef struct {
	char *mask;
	int not_flags; /* do not let this mask use these flags.. */
} USER_MASK_REC;

/* User specific flags */
typedef struct {
	char *nick;
	int flags;
	char *password;

	GSList *masks;
	GHashTable *channels;

	int not_flags; /* active not_flags based on current host mask,
	                  botuser_find() updates this */
        time_t last_modify; /* last time the user settings were modified */
} USER_REC;

int botuser_flags2value(const char *flags);
char *botuser_value2flags(int value);

USER_REC *botuser_find(const char *nick, const char *host);
USER_REC *botuser_find_rec(CHANNEL_REC *channel, NICK_REC *nick);

USER_REC *botuser_add(const char *nick);
void botuser_set_flags(USER_REC *user, int flags);
void botuser_set_channel_flags(USER_REC *user, const char *channel, int flags);

USER_MASK_REC *botuser_add_mask(USER_REC *user, const char *mask);
void botuser_set_mask_notflags(USER_REC *user, const char *mask, int not_flags);

void botuser_set_password(USER_REC *user, const char *password);
int botuser_verify_password(USER_REC *user, const char *password);

void botuser_save(const char *fname);

#endif
