#ifndef IRSSI_IRC_DCC_DCC_QUEUE_H
#define IRSSI_IRC_DCC_DCC_QUEUE_H

#include <irssi/src/irc/dcc/dcc-chat.h>

enum {
	DCC_QUEUE_NORMAL,
	DCC_QUEUE_PREPEND,
	DCC_QUEUE_APPEND
};

typedef struct {
	CHAT_DCC_REC *chat;
	char *servertag;
	char *nick;
	char *file;
	int passive; /* for passive DCCs */
} DCC_QUEUE_REC;

/* create a new queue. returns it's designation number (int) */
int dcc_queue_new(void);

void dcc_queue_free(int queue);

/* finds an old queue and returns it's designation number (int). if not
   found return -1 */
int dcc_queue_old(const char *nick, const char *servertag);

/* adds nick/fname/servertag triplet into queue */
void dcc_queue_add(int queue, int mode, const char *nick, const char *fname,
		   const char *servertag, CHAT_DCC_REC *chat, int passive);

int dcc_queue_remove_head(int queue);

int dcc_queue_remove_tail(int queue);

/* return the first entry from queue */
DCC_QUEUE_REC *dcc_queue_get_next(int queue);

GSList *dcc_queue_get_queue(int queue);

void dcc_queue_init(void);
void dcc_queue_deinit(void);

#endif
