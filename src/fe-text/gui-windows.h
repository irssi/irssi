#ifndef __GUI_WINDOWS_H
#define __GUI_WINDOWS_H

#include "mainwindows.h"
#include "textbuffer-view.h"

#define WINDOW_GUI(a) ((GUI_WINDOW_REC *) ((a)->gui_data))

#define is_window_visible(win) \
    (WINDOW_GUI(win)->parent->active == (win))

typedef struct {
	MAIN_WINDOW_REC *parent;
	TEXT_BUFFER_VIEW_REC *view;

	unsigned int use_insert_after:1;
        LINE_REC *insert_after;
} GUI_WINDOW_REC;

void gui_windows_init(void);
void gui_windows_deinit(void);

WINDOW_REC *gui_window_create(MAIN_WINDOW_REC *parent);

void gui_window_resize(WINDOW_REC *window, int width, int height);
void gui_window_reparent(WINDOW_REC *window, MAIN_WINDOW_REC *parent);

#define gui_window_redraw(window) \
	textbuffer_view_redraw(WINDOW_GUI(window)->view)

void gui_window_scroll(WINDOW_REC *window, int lines);
void gui_window_scroll_line(WINDOW_REC *window, LINE_REC *line);

void window_update_prompt(void);

#endif
