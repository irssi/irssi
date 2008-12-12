#ifndef __TEXTBUFFER_VIEW_H
#define __TEXTBUFFER_VIEW_H

#include "textbuffer.h"
#include "term.h"

typedef struct _TEXT_BUFFER_VIEW_REC TEXT_BUFFER_VIEW_REC;

/* if ypos == -1, don't print anything, just return the indent size */
typedef int (*INDENT_FUNC) (TEXT_BUFFER_VIEW_REC *view,
			    LINE_REC *line, int ypos);

typedef struct {
	const unsigned char *start;
	int indent;
        INDENT_FUNC indent_func;
	int color;

	/* first word in line belong to the end of the last word in
	   previous line */
	unsigned int continues:1;
} LINE_CACHE_SUB_REC;

typedef struct {
	time_t last_access;

	int count; /* number of real lines */

	/* variable sized array, actually. starts from the second line,
	   so size of it is count-1 */
	LINE_CACHE_SUB_REC lines[1];
} LINE_CACHE_REC;

typedef struct {
	int refcount;
	int width;

	GHashTable *line_cache;

	/* should contain the same value for each cache that uses the
	   same buffer */
	unsigned char update_counter;
        /* number of real lines used by the last line in buffer */
	int last_linecount;
} TEXT_BUFFER_CACHE_REC;

struct _TEXT_BUFFER_VIEW_REC {
	TEXT_BUFFER_REC *buffer;
	GSList *siblings; /* other views that use the same buffer */

        TERM_WINDOW *window;
	int width, height;

	int default_indent;
        INDENT_FUNC default_indent_func;
	unsigned int longword_noindent:1;
	unsigned int scroll:1; /* scroll down automatically when at bottom */
	unsigned int utf8:1; /* use UTF8 in this view */

	TEXT_BUFFER_CACHE_REC *cache;
	int ypos; /* cursor position - visible area is 0..height-1 */

	LINE_REC *startline; /* line at the top of the screen */
	int subline; /* number of "real lines" to skip from `startline' */

        /* marks the bottom of the text buffer */
	LINE_REC *bottom_startline;
	int bottom_subline;

	/* how many empty lines are in screen. a screenful when started
	   or used /CLEAR */
	int empty_linecount; 
        /* window is at the bottom of the text buffer */
	unsigned int bottom:1;
        /* if !bottom - new text has been printed since we were at bottom */
	unsigned int more_text:1;
        /* Window needs a redraw */
	unsigned int dirty:1;

	/* Bookmarks to the lines in the buffer - removed automatically
	   when the line gets removed from buffer */
        GHashTable *bookmarks;
};

/* Create new view. */
TEXT_BUFFER_VIEW_REC *textbuffer_view_create(TEXT_BUFFER_REC *buffer,
					     int width, int height,
					     int scroll, int utf8);
/* Destroy the view. */
void textbuffer_view_destroy(TEXT_BUFFER_VIEW_REC *view);
/* Change the default indent position */
void textbuffer_view_set_default_indent(TEXT_BUFFER_VIEW_REC *view,
					int default_indent,
					int longword_noindent,
					INDENT_FUNC indent_func);
void textbuffer_views_unregister_indent_func(INDENT_FUNC indent_func);

void textbuffer_view_set_scroll(TEXT_BUFFER_VIEW_REC *view, int scroll);
void textbuffer_view_set_utf8(TEXT_BUFFER_VIEW_REC *view, int utf8);

/* Resize the view. */
void textbuffer_view_resize(TEXT_BUFFER_VIEW_REC *view, int width, int height);
/* Clear the view, don't actually remove any lines from buffer. */
void textbuffer_view_clear(TEXT_BUFFER_VIEW_REC *view);

#define textbuffer_view_get_lines(view) \
        ((view)->buffer->first_line)

/* Scroll the view up/down */
void textbuffer_view_scroll(TEXT_BUFFER_VIEW_REC *view, int lines);
/* Scroll to specified line */
void textbuffer_view_scroll_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line);
/* Return line cache */
LINE_CACHE_REC *textbuffer_view_get_line_cache(TEXT_BUFFER_VIEW_REC *view,
					       LINE_REC *line);

/*
   Functions for manipulating the text buffer, using these commands update
   all views that use the buffer.
*/

/* Update some line in the buffer which has been modified using
   textbuffer_append() or textbuffer_insert(). */
void textbuffer_view_insert_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line);
/* Remove one line from buffer. */
void textbuffer_view_remove_line(TEXT_BUFFER_VIEW_REC *view, LINE_REC *line);
/* Remove all lines from buffer. */
void textbuffer_view_remove_all_lines(TEXT_BUFFER_VIEW_REC *view);
void textbuffer_view_remove_lines_by_level(TEXT_BUFFER_VIEW_REC *view, int level);

/* Set a bookmark in view */
void textbuffer_view_set_bookmark(TEXT_BUFFER_VIEW_REC *view,
				  const char *name, LINE_REC *line);
/* Set a bookmark in view to the bottom line */
void textbuffer_view_set_bookmark_bottom(TEXT_BUFFER_VIEW_REC *view,
					 const char *name);
/* Return the line for bookmark */
LINE_REC *textbuffer_view_get_bookmark(TEXT_BUFFER_VIEW_REC *view,
				       const char *name);

/* Specify window where the changes in view should be drawn,
   NULL disables it. */
void textbuffer_view_set_window(TEXT_BUFFER_VIEW_REC *view,
				TERM_WINDOW *window);
/* Redraw the view */
void textbuffer_view_redraw(TEXT_BUFFER_VIEW_REC *view);

void textbuffer_view_init(void);
void textbuffer_view_deinit(void);

#endif
