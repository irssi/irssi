#ifndef __FE_QUERIES_H
#define __FE_QUERIES_H

#include "queries.h"

/* Return query where to put the private message. */
QUERY_REC *privmsg_get_query(SERVER_REC *server, const char *nick,
			     int own, int level);

void fe_queries_init(void);
void fe_queries_deinit(void);

#endif
