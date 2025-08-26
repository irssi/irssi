#ifndef IRSSI_FE_TEXT_GUI_PRINTTEXT_H
#define IRSSI_FE_TEXT_GUI_PRINTTEXT_H

#include <irssi/src/fe-text/gui-windows.h>
#include <irssi/src/fe-text/textbuffer-view.h>
#include <irssi/src/fe-common/core/formats.h>

extern int mirc_colors[];

void gui_printtext_init(void);
void gui_printtext_deinit(void);

void gui_register_indent_func(const char *name, INDENT_FUNC func);
void gui_unregister_indent_func(const char *name, INDENT_FUNC func);

void gui_set_default_indent(const char *name);
INDENT_FUNC get_default_indent_func(void);

void gui_printtext(int xpos, int ypos, const char *str);
void gui_printtext_internal(int xpos, int ypos, const char *str);
void gui_printtext_after(TEXT_DEST_REC *dest, LINE_REC *prev, const char *str);
void gui_printtext_after_time(TEXT_DEST_REC *dest, LINE_REC *prev, const char *str, time_t time);
void gui_printtext_window_border(int xpos, int ypos);
void gui_printtext_get_colors(int *flags, int *fg, int *bg, int *attr);

#endif
