#ifndef __SERVERS_REDIRECT_H
#define __SERVERS_REDIRECT_H

typedef struct {
	int last; /* number of "last" events at the start of the events list */
	GSList *events; /* char* list of events */
} REDIRECT_CMD_REC;

typedef struct {
	char *name; /* event name */

	char *arg; /* argument for event we are expecting or NULL */
	int argpos; /* argument position */

	int group; /* group of events this belongs to */
	int last; /* if this event is received, remove all the events in this group */
}
REDIRECT_REC;

void server_redirect_init(SERVER_REC *server, const char *command, int last, ...);
void server_redirect_initv(SERVER_REC *server, const char *command, int last, GSList *list);
/* ... = char *event1, char *event2, ..., NULL */

void server_redirect_event(SERVER_REC *server, const char *arg, int last, ...);
/* ... = char *event, char *callback_signal, int argpos, ..., NULL */

int server_redirect_single_event(SERVER_REC *server, const char *arg, int last, int group,
				 const char *event, const char *signal, int argpos);
void server_redirect_default(SERVER_REC *server, const char *command);
void server_redirect_remove_next(SERVER_REC *server, const char *event, GSList *item);
GSList *server_redirect_getqueue(SERVER_REC *server, const char *event, const char *args);

void servers_redirect_init(void);
void servers_redirect_deinit(void);

#endif
