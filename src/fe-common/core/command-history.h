#ifndef __COMMAND_HISTORY_H
#define __COMMAND_HISTORY_H

#include "fe-windows.h"

void command_history_init(void);
void command_history_deinit(void);

void command_history_add(WINDOW_REC *window, const char *text, int prepend);

const char *command_history_prev(WINDOW_REC *window, const char *text);
const char *command_history_next(WINDOW_REC *window, const char *text);

void command_history_clear_pos(WINDOW_REC *window);

#endif
