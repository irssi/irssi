#ifndef __QUERIES_H
#define __QUERIES_H

#include "servers.h"

/* Returns QUERY_REC if it's query, NULL if it isn't. */
#define QUERY(query) \
	MODULE_CHECK_CAST_MODULE(query, QUERY_REC, type, \
			      "WINDOW ITEM TYPE", "QUERY")

#define IS_QUERY(query) \
	(QUERY(query) ? TRUE : FALSE)

#define STRUCT_SERVER_REC SERVER_REC
typedef struct {
#include "query-rec.h"
} QUERY_REC;

extern GSList *queries;

void query_init(QUERY_REC *query, int automatic);
void query_destroy(QUERY_REC *query);

/* Create a new query */
QUERY_REC *query_create(int chat_type, SERVER_REC *server,
			const char *nick, int automatic);

/* Find query by name, if `server' is NULL, search from all servers */
QUERY_REC *query_find(SERVER_REC *server, const char *nick);

void query_change_nick(QUERY_REC *query, const char *nick);
void query_change_address(QUERY_REC *query, const char *address);
void query_change_server(QUERY_REC *query, SERVER_REC *server);

void queries_init(void);
void queries_deinit(void);

#endif
