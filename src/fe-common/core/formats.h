#ifndef __FORMATS_H
#define __FORMATS_H

#include "themes.h"
#include "windows.h"

enum {
	FORMAT_STRING,
	FORMAT_INT,
	FORMAT_LONG,
	FORMAT_FLOAT
};

struct _FORMAT_REC {
	char *tag;
	char *def;

	int params;
	int paramtypes[10];
};

typedef struct {
	WINDOW_REC *window;
	void *server;
	const char *target;
	int level;
} TEXT_DEST_REC;

char *format_get_text(const char *module, WINDOW_REC *window,
		      void *server, const char *target,
		      int formatnum, ...);

char *format_get_text_theme(THEME_REC *theme, const char *module,
			    TEXT_DEST_REC *dest, int formatnum, ...);
char *format_get_text_theme_args(THEME_REC *theme, const char *module,
				 TEXT_DEST_REC *dest, int formatnum,
				 va_list va);

/* add `linestart' to start of each line in `text'. `text' may contain
   multiple lines separated with \n. */
char *format_add_linestart(const char *text, const char *linestart);

/* return the "-!- " text at the start of the line */
char *format_get_line_start(THEME_REC *theme, TEXT_DEST_REC *dest);


/* "private" functions for printtext */
void format_create_dest(TEXT_DEST_REC *dest,
			void *server, const char *target,
			int level, WINDOW_REC *window);

#define FORMAT_COLOR_NOCHANGE	('0'-1)

#define FORMAT_STYLE_SPECIAL	0x60
#define FORMAT_STYLE_UNDERLINE	(0x01 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_BOLD	(0x02 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_REVERSE	(0x03 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_INDENT	(0x04 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_DEFAULTS	(0x05 + FORMAT_STYLE_SPECIAL)
int format_expand_styles(GString *out, char format, TEXT_DEST_REC *dest);

#endif
