#ifndef __IRC_QUERIES_H
#define __IRC_QUERIES_H

#include "queries.h"
#include "irc-servers.h"

/* Returns IRC_QUERY_REC if it's IRC query, NULL if it isn't. */
#define IRC_QUERY(query) \
	MODULE_CHECK_CAST(query, QUERY_REC, chat_type, "IRC QUERY")

#define IS_IRC_QUERY(query) \
	(IRC_QUERY(query) ? TRUE : FALSE)

void irc_queries_init(void);
void irc_queries_deinit(void);

#define irc_query_find(server, name) \
	query_find(SERVER(server), name)

QUERY_REC *irc_query_create(IRC_SERVER_REC *server,
			    const char *nick, int automatic);

#endif
