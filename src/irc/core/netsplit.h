#ifndef __NETSPLIT_H
#define __NETSPLIT_H

#include "nicklist.h"

typedef struct {
	char *server;
	char *destserver;
	int count;

	time_t last; /* last time we received a QUIT msg here */
} NETSPLIT_SERVER_REC;

typedef struct {
	NETSPLIT_SERVER_REC *server;

	char *nick;
	char *address;
	GSList *channels;

	int printed:1;
	time_t destroy;
} NETSPLIT_REC;

typedef struct {
	char *name;
	NICK_REC nick;
} NETSPLIT_CHAN_REC;

void netsplit_init(void);
void netsplit_deinit(void);

NETSPLIT_REC *netsplit_find(IRC_SERVER_REC *server, const char *nick, const char *address);
NICK_REC *netsplit_find_channel(IRC_SERVER_REC *server, const char *nick, const char *address, const char *channel);

int quitmsg_is_split(const char *msg);

#endif
