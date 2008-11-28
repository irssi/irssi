#ifndef __NICKLIST_H
#define __NICKLIST_H

/* Returns NICK_REC if it's nick, NULL if it isn't. */
#define NICK(server) \
	MODULE_CHECK_CAST(server, NICK_REC, type, "NICK")

#define IS_NICK(server) \
	(NICK(server) ? TRUE : FALSE)

#define	MAX_USER_PREFIXES 7 /* Max prefixes kept for any user-in-chan. 7+1 is a memory unit */

struct _NICK_REC {
#include "nick-rec.h"
};

/* Add new nick to list */
void nicklist_insert(CHANNEL_REC *channel, NICK_REC *nick);
/* Set host address for nick */
void nicklist_set_host(CHANNEL_REC *channel, NICK_REC *nick, const char *host);
/* Remove nick from list */
void nicklist_remove(CHANNEL_REC *channel, NICK_REC *nick);
/* Change nick */
void nicklist_rename(SERVER_REC *server, const char *old_nick,
		     const char *new_nick);
void nicklist_rename_unique(SERVER_REC *server,
			    void *old_nick_id, const char *old_nick,
			    void *new_nick_id, const char *new_nick);

/* Find nick */
NICK_REC *nicklist_find(CHANNEL_REC *channel, const char *nick);
NICK_REC *nicklist_find_unique(CHANNEL_REC *channel, const char *nick,
			       void *id);
/* Find nick mask, wildcards allowed */
NICK_REC *nicklist_find_mask(CHANNEL_REC *channel, const char *mask);
/* Get list of nicks that match the mask */
GSList *nicklist_find_multiple(CHANNEL_REC *channel, const char *mask);
/* Get list of nicks */
GSList *nicklist_getnicks(CHANNEL_REC *channel);
/* Get all the nick records of `nick'. Returns channel, nick, channel, ... */
GSList *nicklist_get_same(SERVER_REC *server, const char *nick);
GSList *nicklist_get_same_unique(SERVER_REC *server, void *id);

/* Update specified nick's status in server. */
void nicklist_update_flags(SERVER_REC *server, const char *nick,
			   int gone, int ircop);
void nicklist_update_flags_unique(SERVER_REC *server, void *id,
			   int gone, int ircop);

/* Specify which nick in channel is ours */
void nicklist_set_own(CHANNEL_REC *channel, NICK_REC *nick);

/* Nick record comparison for sort functions */
int nicklist_compare(NICK_REC *p1, NICK_REC *p2, const char *nick_prefix);

/* Check is `msg' is meant for `nick'. */
int nick_match_msg(CHANNEL_REC *channel, const char *msg, const char *nick);

void nicklist_init(void);
void nicklist_deinit(void);

#endif
