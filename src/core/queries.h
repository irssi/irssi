#ifndef __QUERIES_H
#define __QUERIES_H

#include "servers.h"

#define IS_QUERY(query) \
	((query) != NULL && \
	 module_find_id("QUERY", ((QUERY_REC *) (query))->type) != -1)

/* Returns QUERY_REC if it's query, NULL if it isn't. */
#define QUERY(query) \
	(IS_QUERY(query) ? (QUERY_REC *) (query) : NULL)

#define STRUCT_SERVER_REC SERVER_REC
typedef struct {
#include "query-rec.h"
} QUERY_REC;

extern GSList *queries;

void query_init(QUERY_REC *query, int automatic);
void query_destroy(QUERY_REC *query);

/* Find query by name, if `server' is NULL, search from all servers */
QUERY_REC *query_find(SERVER_REC *server, const char *nick);

void query_change_server(QUERY_REC *query, SERVER_REC *server);

void queries_init(void);
void queries_deinit(void);

#endif
