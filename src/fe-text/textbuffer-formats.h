#ifndef IRSSI_FE_TEXT_TEXTBUFFER_FORMATS_H
#define IRSSI_FE_TEXT_TEXTBUFFER_FORMATS_H

#include <irssi/src/fe-text/textbuffer.h>

typedef struct _TEXT_BUFFER_FORMAT_REC {
	char *module;
	char *format;
	char *server_tag;
	char *target;
	char *nick;
	char **args;
	int nargs;
	int flags;
} TEXT_BUFFER_FORMAT_REC;

void textbuffer_format_rec_free(TEXT_BUFFER_FORMAT_REC *rec);
LINE_REC *textbuffer_reformat_line(WINDOW_REC *window, LINE_REC *line);
void textbuffer_formats_init(void);
void textbuffer_formats_deinit(void);

#endif
