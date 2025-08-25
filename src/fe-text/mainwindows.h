#ifndef IRSSI_FE_TEXT_MAINWINDOWS_H
#define IRSSI_FE_TEXT_MAINWINDOWS_H

#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-text/term.h>

#define WINDOW_MIN_SIZE 2
#define NEW_WINDOW_WIDTH 20 /* must be >= MIN_SCREEN_WIDTH defined in term.c */

#define MAIN_WINDOW_TEXT_HEIGHT(window) ((window)->height - (window)->statusbar_lines)

#define MAIN_WINDOW_TEXT_WIDTH(window) ((window)->width - (window)->statusbar_columns)

typedef struct {
	WINDOW_REC *active;

	TERM_WINDOW *screen_win;
	int sticky_windows; /* number of sticky windows */

	int first_line,
	    last_line; /* first/last line used by this window (0..x) (includes statusbars) */
	int first_column,
	    last_column;   /* first/last column used by this window (0..x) (includes statusbars) */
	int width, height; /* width/height of the window (includes statusbars) */

	GSList *statusbars;
	int statusbar_lines_top, statusbar_lines_bottom;
	int statusbar_lines; /* top+bottom */
	int statusbar_columns_left, statusbar_columns_right;
	int statusbar_columns; /* left+right */

	unsigned int dirty : 1;      /* This window needs a redraw */
	unsigned int size_dirty : 1; /* We'll need to resize the window, but haven't got around
	                                doing it just yet. */
} MAIN_WINDOW_REC;

typedef struct {
	char *color;
	TERM_WINDOW *window;
} MAIN_WINDOW_BORDER_REC;

extern GSList *mainwindows;
extern MAIN_WINDOW_REC *active_mainwin;
extern MAIN_WINDOW_BORDER_REC *clrtoeol_info;
extern int screen_reserved_top, screen_reserved_bottom;

void mainwindows_init(void);
void mainwindows_deinit(void);

MAIN_WINDOW_REC *mainwindow_create(int);
void mainwindow_destroy(MAIN_WINDOW_REC *window);

void mainwindows_redraw(void);
void mainwindows_recreate(void);

/* Change the window height - the height includes the lines needed for
   statusbars. If resize_lower is TRUE, the lower window is first tried
   to be resized instead of upper window. */
void mainwindow_set_size(MAIN_WINDOW_REC *window, int height, int resize_lower);
void mainwindow_set_rsize(MAIN_WINDOW_REC *window, int width);
void mainwindows_resize(int width, int height);

void mainwindow_change_active(MAIN_WINDOW_REC *mainwin, WINDOW_REC *skip_window);

int mainwindows_reserve_lines(int top, int bottom);
int mainwindow_set_statusbar_lines(MAIN_WINDOW_REC *window, int top, int bottom);
void mainwindows_redraw_dirty(void);

/* Reserve columns at left/right of a main window (for side panels). */
int mainwindows_reserve_columns(int left, int right);
int mainwindow_set_statusbar_columns(MAIN_WINDOW_REC *window, int left, int right);

GSList *mainwindows_get_sorted(int reverse);
GSList *mainwindows_get_line(MAIN_WINDOW_REC *rec);

#endif
