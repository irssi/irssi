#ifndef __GUI_READLINE_H
#define __GUI_READLINE_H

extern char *cutbuffer;

void readline(void);
time_t get_idle_time(void);

void gui_readline_init(void);
void gui_readline_deinit(void);

#endif
