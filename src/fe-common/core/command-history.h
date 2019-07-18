#ifndef IRSSI_FE_COMMON_CORE_COMMAND_HISTORY_H
#define IRSSI_FE_COMMON_CORE_COMMAND_HISTORY_H

#include <irssi/src/common.h>

typedef struct {
	char *name;

	GList *pos;
	int lines;

	int refcount;
	unsigned int redo:1;
} HISTORY_REC;

typedef struct {
	const char *text;
	HISTORY_REC *history;
	time_t time;
} HISTORY_ENTRY_REC;

HISTORY_REC *command_history_find(HISTORY_REC *history);
HISTORY_REC *command_history_find_name(const char *name);

HISTORY_REC *command_history_current(WINDOW_REC *window);

void command_history_init(void);
void command_history_deinit(void);

void command_history_add(HISTORY_REC *history, const char *text);
void command_history_load_entry(time_t time, HISTORY_REC *history, const char *text);
gboolean command_history_delete_entry(time_t history_time, HISTORY_REC *history, const char *text);

GList *command_history_list_last(HISTORY_REC *history);
GList *command_history_list_first(HISTORY_REC *history);
GList *command_history_list_prev(HISTORY_REC *history, GList *pos);
GList *command_history_list_next(HISTORY_REC *history, GList *pos);

const char *command_history_prev(WINDOW_REC *window, const char *text);
const char *command_history_next(WINDOW_REC *window, const char *text);
const char *command_global_history_prev(WINDOW_REC *window, const char *text);
const char *command_global_history_next(WINDOW_REC *window, const char *text);
const char *command_history_delete_current(WINDOW_REC *window, const char *text);

void command_history_clear_pos(WINDOW_REC *window);

HISTORY_REC *command_history_create(const char *name);
void command_history_clear(HISTORY_REC *history);
void command_history_destroy(HISTORY_REC *history);
void command_history_link(const char *name);
void command_history_unlink(const char *name);

#endif
