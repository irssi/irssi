#ifndef __GUI_MAINWINDOWS_H
#define __GUI_MAINWINDOWS_H

#include "windows.h"

typedef struct {
	WINDOW_REC *active;
	GList *children;

	int destroying;
} MAIN_WINDOW_REC;

extern GList *mainwindows;

void gui_mainwindows_init(void);
void gui_mainwindows_deinit(void);

MAIN_WINDOW_REC *gui_mainwindow_create(void);
void gui_mainwindow_destroy(MAIN_WINDOW_REC *window);

#endif
