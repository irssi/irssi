#ifndef __MAINWINDOWS_H
#define __MAINWINDOWS_H

#include "fe-windows.h"
#include "screen.h"

#define WINDOW_MIN_SIZE 2

typedef struct {
	WINDOW_REC *active;
        GSList *sticky_windows; /* list of windows allowed to show only in this mainwindow */

#ifdef USE_CURSES_WINDOWS
	WINDOW *curses_win;
#else
#error disable-curses-windows is currently broken /* FIXME */
#endif
	int first_line, last_line, width, height;
	int statusbar_lines;
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

int mainwindows_reserve_lines(int count, int up);
GSList *mainwindows_get_sorted(int reverse);

#endif
