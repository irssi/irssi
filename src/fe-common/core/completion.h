#ifndef __COMPLETION_H
#define __COMPLETION_H

#include "window-items.h"

/* automatic word completion - called when space/enter is pressed */
char *auto_word_complete(const char *line, int *pos);
/* manual word completion - called when TAB is pressed */
char *word_complete(WINDOW_REC *window, const char *line, int *pos);

GList *filename_complete(const char *path);

void completion_init(void);
void completion_deinit(void);

#endif
