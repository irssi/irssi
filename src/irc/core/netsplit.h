#ifndef __NETSPLIT_H
#define __NETSPLIT_H

#include "nicklist.h"

typedef struct {
	char *server;
	char *destserver;
	int count;
        int prints; /* temp variable */

	time_t last; /* last time we received a QUIT msg here */
} NETSPLIT_SERVER_REC;

typedef struct {
	NETSPLIT_SERVER_REC *server;

	char *nick;
	char *address;
	GSList *channels;

	unsigned int printed:1;
	time_t destroy;
} NETSPLIT_REC;

typedef struct {
	char *name;
	unsigned int op:1;
	unsigned int halfop:1;
	unsigned int voice:1;
	char prefixes[MAX_USER_PREFIXES+1];
} NETSPLIT_CHAN_REC;

void netsplit_init(void);
void netsplit_deinit(void);

NETSPLIT_REC *netsplit_find(IRC_SERVER_REC *server, const char *nick, const char *address);
NETSPLIT_CHAN_REC *netsplit_find_channel(IRC_SERVER_REC *server, const char *nick, const char *address, const char *channel);

/* check if quit message is a netsplit message */
int quitmsg_is_split(const char *msg);

#endif
