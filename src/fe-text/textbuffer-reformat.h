#ifndef __TEXTBUFFER_REFORMAT_H
#define __TEXTBUFFER_REFORMAT_H

void textbuffer_reformat_line(WINDOW_REC *window, LINE_REC *line);

void textbuffer_reformat_init(void);
void textbuffer_reformat_deinit(void);

#endif
