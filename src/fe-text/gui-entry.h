#ifndef __GUI_ENTRY_H
#define __GUI_ENTRY_H

typedef struct {
	int text_len, text_alloc; /* as shorts, not chars */
	unichar *text;

        int cutbuffer_len;
	unichar *cutbuffer;

        /* all as shorts, not chars */
	int xpos, ypos, width; /* entry position in screen */
	int pos, scrstart, scrpos; /* cursor position */
        int hidden; /* print the chars as spaces in input line (useful for passwords) */

	int promptlen;
	char *prompt;

	int redraw_needed_from;
	unsigned int utf8:1;
} GUI_ENTRY_REC;

extern GUI_ENTRY_REC *active_entry;

GUI_ENTRY_REC *gui_entry_create(int xpos, int ypos, int width, int utf8);
void gui_entry_destroy(GUI_ENTRY_REC *entry);

void gui_entry_move(GUI_ENTRY_REC *entry, int xpos, int ypos, int width);
void gui_entry_set_active(GUI_ENTRY_REC *entry);

void gui_entry_set_prompt(GUI_ENTRY_REC *entry, const char *str);
void gui_entry_set_hidden(GUI_ENTRY_REC *entry, int hidden);
void gui_entry_set_utf8(GUI_ENTRY_REC *entry, int utf8);

void gui_entry_set_text(GUI_ENTRY_REC *entry, const char *str);
char *gui_entry_get_text(GUI_ENTRY_REC *entry);
char *gui_entry_get_text_and_pos(GUI_ENTRY_REC *entry, int *pos);

void gui_entry_insert_text(GUI_ENTRY_REC *entry, const char *str);
void gui_entry_insert_char(GUI_ENTRY_REC *entry, unichar chr);

char *gui_entry_get_cutbuffer(GUI_ENTRY_REC *entry);
void gui_entry_erase_to(GUI_ENTRY_REC *entry, int pos, int update_cutbuffer);
void gui_entry_erase(GUI_ENTRY_REC *entry, int size, int update_cutbuffer);
void gui_entry_erase_cell(GUI_ENTRY_REC *entry);
void gui_entry_erase_word(GUI_ENTRY_REC *entry, int to_space);
void gui_entry_erase_next_word(GUI_ENTRY_REC *entry, int to_space);

void gui_entry_transpose_chars(GUI_ENTRY_REC *entry);
void gui_entry_transpose_words(GUI_ENTRY_REC *entry);

void gui_entry_capitalize_word(GUI_ENTRY_REC *entry);
void gui_entry_downcase_word(GUI_ENTRY_REC *entry);
void gui_entry_upcase_word(GUI_ENTRY_REC *entry);

int gui_entry_get_pos(GUI_ENTRY_REC *entry);
void gui_entry_set_pos(GUI_ENTRY_REC *entry, int pos);
void gui_entry_move_pos(GUI_ENTRY_REC *entry, int pos);
void gui_entry_move_words(GUI_ENTRY_REC *entry, int count, int to_space);

void gui_entry_redraw(GUI_ENTRY_REC *entry);

#endif
