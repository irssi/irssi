#ifndef __GUI_WINDOWS_H
#define __GUI_WINDOWS_H

#include "server.h"
#include "mainwindows.h"

#define WINDOW_GUI(a) ((GUI_WINDOW_REC *) ((a)->gui_data))

#define is_window_visible(win) \
    (WINDOW_GUI(win)->parent->active == (win))

#define LINE_TEXT_CHUNK_SIZE 2048

/* 7 first bits of LINE_REC's info byte. */
enum {
	LINE_CMD_EOL=0x80,	/* line ends here. */
	LINE_CMD_CONTINUE,	/* line continues in next block */
	LINE_CMD_OVERFLOW,	/* buffer overflow! */
	LINE_CMD_COLOR0,	/* change to black, would be same as \0\0 but it breaks things.. */
	LINE_CMD_COLOR8,	/* change to dark grey, normally 8 = bold black */
	LINE_CMD_UNDERLINE,	/* enable/disable underlining */
	LINE_CMD_INDENT		/* if line is split, indent it at this position */
};

typedef struct {
	char *start;
	int indent;
	int color;
} LINE_CACHE_SUB_REC;

typedef struct {
	time_t last_access;

	int count; /* number of real lines */
        LINE_CACHE_SUB_REC *lines;
} LINE_CACHE_REC;

typedef struct {
	/* text in the line. \0 means that the next char will be a
	   color or command. <= 127 = color or if 8.bit is set, the
	   first 7 bits are the command. See LINE_CMD_xxxx.

	   DO NOT ADD BLACK WITH \0\0 - this will break things. Use
	   LINE_CMD_COLOR0 instead. */
	char *text;

	int level;
	time_t time;
} LINE_REC;

typedef struct {
	char buffer[LINE_TEXT_CHUNK_SIZE];
	char overflow[2];
	int pos;
	int lines;
} TEXT_CHUNK_REC;

typedef struct {
	MAIN_WINDOW_REC *parent;

	GMemChunk *line_chunk;
	GSList *text_chunks;
	GList *lines;
	GHashTable *line_cache;

	LINE_REC *cur_line;
	TEXT_CHUNK_REC *cur_text;

	int xpos, ypos; /* cursor position in screen */
	GList *startline; /* line at the top of the screen */
	int subline; /* number of "real lines" to skip from `startline' */

	GList *bottom_startline; /* marks the bottom of the text buffer */
	int bottom_subline;
	int empty_linecount; /* how many empty lines are in screen.
	                        a screenful when started or used /CLEAR */
	int bottom; /* window is at the bottom of the text buffer */

	/* For /LAST -new and -away */
	GList *lastlog_last_check;
	GList *lastlog_last_away;

	/* for gui-printtext.c */
	int last_subline;
	int last_color, last_flags;
} GUI_WINDOW_REC;

void gui_windows_init(void);
void gui_windows_deinit(void);

WINDOW_REC *gui_window_create(MAIN_WINDOW_REC *parent);

void gui_window_set_server(WINDOW_REC *window, SERVER_REC *server);
GList *gui_window_find_text(WINDOW_REC *window, char *text, GList *startline, int regexp, int fullword);

/* get number of real lines that line record takes */
int gui_window_get_linecount(GUI_WINDOW_REC *gui, LINE_REC *line);
void gui_window_cache_remove(GUI_WINDOW_REC *gui, LINE_REC *line);
int gui_window_line_draw(GUI_WINDOW_REC *gui, LINE_REC *line, int ypos, int skip, int max);

void gui_window_clear(WINDOW_REC *window);
void gui_window_redraw(WINDOW_REC *window);
void gui_window_resize(WINDOW_REC *window, int ychange, int xchange);
void gui_window_reparent(WINDOW_REC *window, MAIN_WINDOW_REC *parent);

#define is_window_bottom(gui) \
	((gui)->ypos >= -1 && (gui)->ypos <= (gui)->parent->last_line-(gui)->parent->first_line)

void window_update_prompt(WINDOW_REC *window);
void gui_window_newline(GUI_WINDOW_REC *gui, int visible);
void gui_window_scroll(WINDOW_REC *window, int lines);
void gui_window_update_ypos(GUI_WINDOW_REC *gui);

#endif
