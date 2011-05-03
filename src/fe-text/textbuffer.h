#ifndef __TEXTBUFFER_H
#define __TEXTBUFFER_H

/* Make sure TEXT_CHUNK_REC is not slightly more than a page, as that
   wastes a lot of memory. */
#define LINE_TEXT_CHUNK_SIZE (16384 - 16)

#define LINE_COLOR_BG		0x20
#define LINE_COLOR_DEFAULT	0x10

/* command values (see _LINE_REC protocol) */
enum {
	LINE_CMD_EOL=0x80,	/* line ends here */
	LINE_CMD_CONTINUE,	/* line continues in next block */
	/* TODO: no longer needed */
	LINE_CMD_COLOR0,	/* change to black, would be same as \0\0 but it breaks things.. */
	LINE_CMD_UNDERLINE,	/* enable/disable underlining */
	LINE_CMD_REVERSE,	/* enable/disable reversed text */
	LINE_CMD_INDENT,	/* if line is split, indent it at this position */
	LINE_CMD_BLINK,		/* enable/disable blink */
	LINE_CMD_BOLD,		/* enable/disable bold */
	LINE_CMD_SELECT_FG,
	LINE_CMD_SELECT_BG

};

typedef struct {
	int level;
	time_t time;
} LINE_INFO_REC;

/* TODO: fixme. */
typedef struct _LINE_REC {
	/* Text in the line. \0 means that the next char will be a
	   color or command.

	   If the 7th bit is set, the lowest 7 bits are the command
	   (see LINE_CMD_xxxx). Otherwise they specify a color change:

	   Bit:
            5 - Setting a background color
            4 - Use "default terminal color"
            0-3 - Color

	   DO NOT ADD BLACK WITH \0\0 - this will break things. Use
	   LINE_CMD_COLOR0 instead. */


     /* NEW COLOUR PROTOCOL:

	0x00 - indicates command or colour.
	0x01 - command follows   (1 byte)
	-- following may be omitted if LINE_CMD_USE_DEFAULT_[FB}G is set.
	0x02 - BG colour follows (1 byte)
	0x04 - FG colour follows (1 byte)

	
	Things that will need to be fixed:

	* textbuffer-view.c:update_cmd_color()
	* textbuffer-view.c:view_line_draw()
	* textbuffer-view.c:view_update_line_cache()

	* textbuffer.c:textbuffer_line2text()
	* textbuffer.c:mark_temp_eol macro
	
	* gui-printtext.c ?
      */
	struct _LINE_REC *prev, *next;

	unsigned char *text;
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
	int last_fg;
	int last_bg;
	int last_flags;
} TEXT_BUFFER_REC;

/* Create new buffer */
TEXT_BUFFER_REC *textbuffer_create(void);
/* Destroy the buffer */
void textbuffer_destroy(TEXT_BUFFER_REC *buffer);

LINE_REC *textbuffer_line_last(TEXT_BUFFER_REC *buffer);
int textbuffer_line_exists_after(LINE_REC *line, LINE_REC *search);

void textbuffer_line_add_colors(TEXT_BUFFER_REC *buffer, LINE_REC **line,
				int fg, int bg, int flags);

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
