#ifndef __TEXTBUFFER_H
#define __TEXTBUFFER_H

/* FIXME: Textbuffer code gets a lot faster in some points when I get rid of
   GList and make prev/next pointers directly in LINE_REC. However, this
   can still wait for a while until I get rid of GList entirely everywhere. */

#define LINE_TEXT_CHUNK_SIZE 16384

enum {
	LINE_CMD_EOL=0x80,	/* line ends here */
	LINE_CMD_CONTINUE,	/* line continues in next block */
	LINE_CMD_COLOR0,	/* change to black, would be same as \0\0 but it breaks things.. */
	LINE_CMD_COLOR8,	/* change to dark grey, normally 8 = bold black */
	LINE_CMD_UNDERLINE,	/* enable/disable underlining */
	LINE_CMD_INDENT,	/* if line is split, indent it at this position */
	LINE_CMD_BLINK,		/* blinking background */
	LINE_CMD_FORMAT,	/* end of line, but next will come the format that was used to create the
				   text in format <module><format_name><arg><arg2...> - fields are separated
				   with \0<format> and last argument ends with \0<eol>. \0<continue> is allowed
				   anywhere */
	LINE_CMD_FORMAT_CONT    /* multiline format, continues to next line */
};

typedef struct {
	int level;
	time_t time;
} LINE_INFO_REC;

typedef struct {
	/* text in the line. \0 means that the next char will be a
	   color or command. <= 127 = color or if 8. bit is set, the
	   first 7 bits are the command. See LINE_CMD_xxxx.

	   DO NOT ADD BLACK WITH \0\0 - this will break things. Use
	   LINE_CMD_COLOR0 instead. */
	unsigned char *text;
        unsigned char refcount;
        LINE_INFO_REC info;
} LINE_REC;

typedef struct {
	unsigned char buffer[LINE_TEXT_CHUNK_SIZE];
	int pos;
	int refcount;
} TEXT_CHUNK_REC;

typedef struct {
	GSList *text_chunks;
	GList *lines;
        int lines_count;

	LINE_REC *cur_line;
	TEXT_CHUNK_REC *cur_text;

	unsigned int last_eol:1;
} TEXT_BUFFER_REC;

/* Create new buffer */
TEXT_BUFFER_REC *textbuffer_create(void);
/* Destroy the buffer */
void textbuffer_destroy(TEXT_BUFFER_REC *buffer);

void textbuffer_line_ref(LINE_REC *line);
void textbuffer_line_unref(TEXT_BUFFER_REC *buffer, LINE_REC *line);
void textbuffer_line_unref_list(TEXT_BUFFER_REC *buffer, GList *list);

/* Append text to buffer. When \0<EOL> is found at the END OF DATA, a new
   line is created. You must send the EOL command before you can do anything
   else with the buffer. */
LINE_REC *textbuffer_append(TEXT_BUFFER_REC *buffer,
			    const unsigned char *data, int len,
			    LINE_INFO_REC *info);
LINE_REC *textbuffer_insert(TEXT_BUFFER_REC *buffer, LINE_REC *insert_after,
			    const unsigned char *data, int len,
			    LINE_INFO_REC *info);

void textbuffer_remove(TEXT_BUFFER_REC *buffer, LINE_REC *line);
/* Removes all lines from buffer, ignoring reference counters */
void textbuffer_remove_all_lines(TEXT_BUFFER_REC *buffer);

void textbuffer_line2text(LINE_REC *line, int coloring, GString *str);
GList *textbuffer_find_text(TEXT_BUFFER_REC *buffer, LINE_REC *startline,
			    int level, int nolevel, const char *text,
			    int regexp, int fullword, int case_sensitive);

void textbuffer_init(void);
void textbuffer_deinit(void);

#endif
