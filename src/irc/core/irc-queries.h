#ifndef __IRC_QUERIES_H
#define __IRC_QUERIES_H

#include "queries.h"
#include "irc-servers.h"

#define IS_IRC_QUERY(query) \
	((query) != NULL && \
	 module_find_id("IRC QUERY", \
	                ((QUERY_REC *) (query))->chat_type) != -1)

/* Returns IRC_QUERY_REC if it's IRC query, NULL if it isn't. */
#define IRC_QUERY(query) \
	(IS_IRC_QUERY(query) ? (QUERY_REC *) (query) : NULL)

void irc_queries_init(void);
void irc_queries_deinit(void);

#define irc_query_find(server, name) \
	query_find(SERVER(server), name)

QUERY_REC *irc_query_create(IRC_SERVER_REC *server,
			    const char *nick, int automatic);

#endif
