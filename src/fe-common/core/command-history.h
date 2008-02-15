#ifndef __COMMAND_HISTORY_H
#define __COMMAND_HISTORY_H

#include "common.h"

typedef struct {
	char *name;

	GList *list, *pos;
	int lines, over_counter;

	int refcount;
} HISTORY_REC;

HISTORY_REC *command_history_find(HISTORY_REC *history);
HISTORY_REC *command_history_find_name(const char *name);

HISTORY_REC *command_history_current(WINDOW_REC *window);

void command_history_init(void);
void command_history_deinit(void);

void command_history_add(HISTORY_REC *history, const char *text);

const char *command_history_prev(WINDOW_REC *window, const char *text);
const char *command_history_next(WINDOW_REC *window, const char *text);

void command_history_clear_pos(WINDOW_REC *window);

HISTORY_REC *command_history_create(const char *name);
void command_history_destroy(HISTORY_REC *history);
void command_history_link(const char *name);
void command_history_unlink(const char *name);

#endif
