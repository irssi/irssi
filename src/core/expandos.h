#ifndef __EXPANDOS_H
#define __EXPANDOS_H

#include "signals.h"

/* first argument of signal must match to active .. */
typedef enum {
        EXPANDO_ARG_NONE = 1,
        EXPANDO_ARG_SERVER,
        EXPANDO_ARG_WINDOW,
	EXPANDO_ARG_WINDOW_ITEM,

	EXPANDO_NEVER /* special: expando never changes */
} ExpandoArg;

typedef char* (*EXPANDO_FUNC)
	(SERVER_REC *server, void *item, int *free_ret);

extern const char *current_expando;

/* Create expando - overrides any existing ones.
   ... = signal, type, ..., NULL - list of signals that might change the
   value of this expando */
void expando_create(const char *key, EXPANDO_FUNC func, ...);
/* Add new signal to expando */
void expando_add_signal(const char *key, const char *signal, ExpandoArg arg);
/* Destroy expando */
void expando_destroy(const char *key, EXPANDO_FUNC func);

void expando_bind(const char *key, int funccount, SIGNAL_FUNC *funcs);
void expando_unbind(const char *key, int funccount, SIGNAL_FUNC *funcs);

/* Returns [<signal id>, EXPANDO_ARG_xxx, <signal id>, ..., -1] */
int *expando_get_signals(const char *key);

/* internal: */
EXPANDO_FUNC expando_find_char(char chr);
EXPANDO_FUNC expando_find_long(const char *key);

void expandos_init(void);
void expandos_deinit(void);

#endif
