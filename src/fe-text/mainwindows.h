#ifndef __MAINWINDOWS_H
#define __MAINWINDOWS_H

#include "fe-windows.h"
#include "screen.h"

#define WINDOW_MIN_SIZE 2

typedef struct {
	WINDOW_REC *active;

	SCREEN_WINDOW *screen_win;
        int sticky_windows; /* number of sticky windows */

	int first_line, last_line; /* first/last line used by this window (0..x), not including statusbar */
	int width, height; /* width/height of the window, not including statusbar */

	int statusbar_lines; /* number of lines the statusbar takes below the window */
	void *statusbar;
	void *statusbar_window_item;
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

int mainwindows_reserve_lines(int count, int up);
GSList *mainwindows_get_sorted(int reverse);

#endif
