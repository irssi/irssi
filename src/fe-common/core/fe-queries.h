#ifndef IRSSI_FE_COMMON_CORE_FE_QUERIES_H
#define IRSSI_FE_COMMON_CORE_FE_QUERIES_H

#include <irssi/src/core/queries.h>

/* Return query where to put the private message. */
QUERY_REC *privmsg_get_query(SERVER_REC *server, const char *nick,
			     int own, int level);

void fe_queries_init(void);
void fe_queries_deinit(void);

#endif
