#ifndef __IRC_QUERIES_H
#define __IRC_QUERIES_H

#include "chat-protocols.h"
#include "queries.h"

/* Returns IRC_QUERY_REC if it's IRC query, NULL if it isn't. */
#define IRC_QUERY(query) \
	PROTO_CHECK_CAST(QUERY(query), QUERY_REC, chat_type, "IRC")

#define IS_IRC_QUERY(query) \
	(IRC_QUERY(query) ? TRUE : FALSE)

void irc_queries_init(void);
void irc_queries_deinit(void);

QUERY_REC *irc_query_find(IRC_SERVER_REC *server, const char *nick);

QUERY_REC *irc_query_create(const char *server_tag,
			    const char *nick, int automatic);

#endif
