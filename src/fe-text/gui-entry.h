#ifndef __GUI_ENTRY_H
#define __GUI_ENTRY_H

void gui_entry_set_prompt(const char *str);

void gui_entry_set_text(const char *str);
char *gui_entry_get_text(void);

void gui_entry_insert_text(const char *str);
void gui_entry_insert_char(char chr);
void gui_entry_erase(int size);

int gui_entry_get_pos(void);
void gui_entry_set_pos(int pos);
void gui_entry_move_pos(int pos);

void gui_entry_redraw(void);

void gui_entry_init(void);
void gui_entry_deinit(void);

#endif
