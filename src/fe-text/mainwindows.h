#ifndef __MAINWINDOWS_H
#define __MAINWINDOWS_H

#include "fe-windows.h"
#include "term.h"

#define WINDOW_MIN_SIZE 2

#define MAIN_WINDOW_TEXT_HEIGHT(window) \
        ((window)->height-(window)->statusbar_lines)

typedef struct {
	WINDOW_REC *active;

	TERM_WINDOW *screen_win;
        int sticky_windows; /* number of sticky windows */

	int first_line, last_line; /* first/last line used by this window (0..x) (includes statusbars) */
	int width, height; /* width/height of the window (includes statusbars) */

	GSList *statusbars;
	int statusbar_lines_top;
	int statusbar_lines_bottom;
	int statusbar_lines; /* top+bottom */

	unsigned int dirty:1; /* This window needs a redraw */
	unsigned int size_dirty:1; /* We'll need to resize the window, but haven't got around doing it just yet. */
} MAIN_WINDOW_REC;

extern GSList *mainwindows;
extern MAIN_WINDOW_REC *active_mainwin;
extern int screen_reserved_top, screen_reserved_bottom;

void mainwindows_init(void);
void mainwindows_deinit(void);

MAIN_WINDOW_REC *mainwindow_create(void);
void mainwindow_destroy(MAIN_WINDOW_REC *window);

void mainwindows_redraw(void);
void mainwindows_recreate(void);

/* Change the window height - the height includes the lines needed for
   statusbars. If resize_lower is TRUE, the lower window is first tried
   to be resized instead of upper window. */
void mainwindow_set_size(MAIN_WINDOW_REC *window, int height,
			 int resize_lower);
void mainwindows_resize(int width, int height);

void mainwindow_change_active(MAIN_WINDOW_REC *mainwin,
			      WINDOW_REC *skip_window);

int mainwindows_reserve_lines(int top, int bottom);
int mainwindow_set_statusbar_lines(MAIN_WINDOW_REC *window,
				   int top, int bottom);
void mainwindows_redraw_dirty(void);

GSList *mainwindows_get_sorted(int reverse);

#endif
