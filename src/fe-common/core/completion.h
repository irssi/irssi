#ifndef __COMPLETION_H
#define __COMPLETION_H

#include "window-items.h"

/* automatic word completion - called when space/enter is pressed */
char *auto_word_complete(const char *line, int *pos);
/* manual word completion - called when TAB is pressed. if erase is TRUE,
   the word is removed from completion list entirely (if possible) and
   next completion is used */
char *word_complete(WINDOW_REC *window, const char *line, int *pos, int erase, int backward);

GList *filename_complete(const char *path, const char *default_path);

void completion_init(void);
void completion_deinit(void);

#endif
