#ifndef __NOTIFYLIST_H
#define __NOTIFYLIST_H

typedef struct {
	char *mask; /* nick part must not contain wildcards */
	char **ircnets; /* if non-NULL, check only from these irc networks */

	/* notify when AWAY status changes (uses /USERHOST) */
	unsigned int away_check:1;
} NOTIFYLIST_REC;

extern GSList *notifies;

void notifylist_init(void);
void notifylist_deinit(void);

NOTIFYLIST_REC *notifylist_add(const char *mask, const char *ircnets,
			       int away_check);
void notifylist_remove(const char *mask);

IRC_SERVER_REC *notifylist_ison(const char *nick, const char *serverlist);
int notifylist_ison_server(IRC_SERVER_REC *server, const char *nick);

/* If `ircnet' is "*", it doesn't matter at all. */
NOTIFYLIST_REC *notifylist_find(const char *mask, const char *ircnet);

int notifylist_ircnets_match(NOTIFYLIST_REC *rec, const char *ircnet);

#endif
