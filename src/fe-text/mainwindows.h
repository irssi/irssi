#ifndef __MAINWINDOWS_H
#define __MAINWINDOWS_H

#include "fe-windows.h"
#include "screen.h"

typedef struct {
	WINDOW_REC *active;

#ifdef USE_CURSES_WINDOWS
	WINDOW *curses_win;
#endif
	int first_line, last_line, lines;
	int statusbar_lines;
	void *statusbar;
	void *statusbar_channel_item;
} MAIN_WINDOW_REC;

extern GSList *mainwindows;
extern MAIN_WINDOW_REC *active_mainwin;

void mainwindows_init(void);
void mainwindows_deinit(void);

MAIN_WINDOW_REC *mainwindow_create(void);
void mainwindow_destroy(MAIN_WINDOW_REC *window);

void mainwindows_redraw(void);
void mainwindows_resize(int ychange, int xchange);
#ifndef USE_CURSES_WINDOWS
void mainwindows_recreate(void);
#endif

int mainwindows_reserve_lines(int count, int up);

#endif
