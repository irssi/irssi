#ifndef __TEXTBUFFER_H
#define __TEXTBUFFER_H

#define LINE_TEXT_CHUNK_SIZE 16384

#define LINE_COLOR_BG		0x20
#define LINE_COLOR_DEFAULT	0x10
#define LINE_COLOR_BOLD		0x08
#define LINE_COLOR_BLINK       	0x08

enum {
	LINE_CMD_EOL=0x80,	/* line ends here */
	LINE_CMD_CONTINUE,	/* line continues in next block */
	LINE_CMD_COLOR0,	/* change to black, would be same as \0\0 but it breaks things.. */
	LINE_CMD_UNDERLINE,	/* enable/disable underlining */
	LINE_CMD_REVERSE,	/* enable/disable reversed text */
	LINE_CMD_INDENT,	/* if line is split, indent it at this position */
	LINE_CMD_INDENT_FUNC,	/* if line is split, use the specified indentation function */
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

typedef struct _LINE_REC {
	/* Text in the line. \0 means that the next char will be a
	   color or command.

	   If the 7th bit is set, the lowest 7 bits are the command
	   (see LINE_CMD_xxxx). Otherwise they specify a color change:

	   Bit:
            5 - Setting a background color
            4 - Use "default terminal color"
            3 - Bold (fg) / blink (bg) - can be used with 4th bit
            0-2 - Color

	   DO NOT ADD BLACK WITH \0\0 - this will break things. Use
	   LINE_CMD_COLOR0 instead. */
	struct _LINE_REC *prev, *next;

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
        LINE_REC *first_line;
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

LINE_REC *textbuffer_line_last(TEXT_BUFFER_REC *buffer);
int textbuffer_line_exists_after(LINE_REC *line, LINE_REC *search);

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
			    int before, int after,
			    int regexp, int fullword, int case_sensitive);

void textbuffer_init(void);
void textbuffer_deinit(void);

#endif
