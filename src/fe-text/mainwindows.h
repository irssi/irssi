#ifndef __MAINWINDOWS_H
#define __MAINWINDOWS_H

#include "fe-windows.h"
#include "screen.h"

#define WINDOW_MIN_SIZE 2

#define MAIN_WINDOW_TEXT_HEIGHT(window) \
        ((window)->height-(window)->statusbar_lines)

typedef struct {
	WINDOW_REC *active;

	SCREEN_WINDOW *screen_win;
        int sticky_windows; /* number of sticky windows */

	int first_line, last_line; /* first/last line used by this window (0..x) (includes statusbars) */
	int width, height; /* width/height of the window (includes statusbars) */

	GSList *statusbars;
	int statusbar_lines_top;
	int statusbar_lines_bottom;
        int statusbar_lines; /* top+bottom */
} MAIN_WINDOW_REC;

extern GSList *mainwindows;
extern MAIN_WINDOW_REC *active_mainwin;

void mainwindows_init(void);
void mainwindows_deinit(void);

MAIN_WINDOW_REC *mainwindow_create(void);
void mainwindow_destroy(MAIN_WINDOW_REC *window);

void mainwindows_redraw(void);
void mainwindows_recreate(void);

void mainwindow_set_size(MAIN_WINDOW_REC *window, int size);
void mainwindows_resize(int width, int height);

void mainwindow_change_active(MAIN_WINDOW_REC *mainwin,
			      WINDOW_REC *skip_window);

int mainwindows_reserve_lines(int top, int bottom);
int mainwindow_set_statusbar_lines(MAIN_WINDOW_REC *window,
				   int top, int bottom);

GSList *mainwindows_get_sorted(int reverse);

#endif
