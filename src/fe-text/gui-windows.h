#ifndef __GUI_WINDOWS_H
#define __GUI_WINDOWS_H

#include "server.h"
#include "gui-mainwindows.h"

#define WINDOW_GUI(a) ((GUI_WINDOW_REC *) ((a)->gui_data))

#define is_window_visible(win) \
    (WINDOW_GUI(win)->parent->active == (win))

#define LINE_TEXT_CHUNK_SIZE 2048

/* 7 first bits of LINE_REC's info byte. */
enum
{
    LINE_CMD_EOL=0x80,	/* line ends here. */
    LINE_CMD_CONTINUE,	/* line continues in next block */
    LINE_CMD_COLOR8,	/* change to dark grey, normally 8 = bold black */
    LINE_CMD_UNDERLINE,	/* enable/disable underlining */
    LINE_CMD_BEEP,	/* beep */
    LINE_CMD_INDENT	/* if line is split, indent it at this position */
};

typedef struct
{
    gchar *text; /* text in the line. \0 means that the next char will be a
                    color or command. <= 127 = color or if 8.bit is set, the
		    first 7 bits are the command. See LINE_CMD_xxxx. */

    gint32 level;
    time_t time;
}
LINE_REC;

typedef struct
{
    gchar buffer[LINE_TEXT_CHUNK_SIZE];
    gint pos;
    gint lines;
}
TEXT_CHUNK_REC;

typedef struct
{
    MAIN_WINDOW_REC *parent;

    GMemChunk *line_chunk;
    GSList *text_chunks;
    GList *lines;

    LINE_REC *cur_line;
    TEXT_CHUNK_REC *cur_text;

    gint xpos, ypos; /* cursor position in screen */
    GList *startline; /* line at the top of the screen */
    gint subline; /* number of "real lines" to skip from `startline' */

    GList *bottom_startline; /* marks the bottom of the text buffer */
    gint bottom_subline;
    gint empty_linecount; /* how many empty lines are in screen.
                             a screenful when started or used /CLEAR */
    gboolean bottom; /* window is at the bottom of the text buffer */

    /* for gui-printtext.c */
    gint last_subline;
    gint last_color, last_flags;
}
GUI_WINDOW_REC;

extern gint first_text_line, last_text_line;

void gui_windows_init(void);
void gui_windows_deinit(void);

WINDOW_REC *gui_window_create(MAIN_WINDOW_REC *parent);

void gui_window_set_server(WINDOW_REC *window, SERVER_REC *server);
GList *gui_window_find_text(WINDOW_REC *window, gchar *text, GList *startline, int regexp, int fullword);

/* get number of real lines that line record takes */
gint gui_window_get_linecount(GUI_WINDOW_REC *gui, LINE_REC *line);
gint gui_window_line_draw(GUI_WINDOW_REC *gui, LINE_REC *line, gint ypos, gint skip, gint max);

void gui_window_clear(WINDOW_REC *window);
void gui_window_redraw(WINDOW_REC *window);
void gui_windows_resize(gint ychange, gboolean xchange);

void gui_window_newline(GUI_WINDOW_REC *gui, gboolean visible);
gint gui_window_update_bottom(GUI_WINDOW_REC *gui, gint lines);
void gui_window_scroll(WINDOW_REC *window, gint lines);

#endif
