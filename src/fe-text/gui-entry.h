#ifndef __GUI_ENTRY_H
#define __GUI_ENTRY_H

typedef struct {
        int cutbuffer_len;
	unichar *cutbuffer;
} GUI_ENTRY_CUTBUFFER_REC;

typedef struct {
	int text_len, text_alloc; /* as shorts, not chars */
	unichar *text;
	char **extents;

	GSList *kill_ring;

        /* all as shorts, not chars */
	int xpos, ypos, width; /* entry position in screen */
	int pos, scrstart, scrpos; /* cursor position */
        int hidden; /* print the chars as spaces in input line (useful for passwords) */

	int promptlen;
	char *prompt;

	int redraw_needed_from;
	unsigned int utf8:1;

	unsigned int previous_append_next_kill:1;
	unsigned int append_next_kill:1;
	unsigned int yank_preceded:1;
	unsigned int uses_extents:1;
} GUI_ENTRY_REC;

typedef enum {
	CUTBUFFER_UPDATE_NOOP,
	CUTBUFFER_UPDATE_REPLACE,
	CUTBUFFER_UPDATE_APPEND,
	CUTBUFFER_UPDATE_PREPEND
} CUTBUFFER_UPDATE_OP;

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
void gui_entry_set_text_and_pos_bytes(GUI_ENTRY_REC *entry, const char *str, int pos_bytes);

void gui_entry_insert_text(GUI_ENTRY_REC *entry, const char *str);
void gui_entry_insert_char(GUI_ENTRY_REC *entry, unichar chr);

char *gui_entry_get_cutbuffer(GUI_ENTRY_REC *entry);
char *gui_entry_get_next_cutbuffer(GUI_ENTRY_REC *entry);
void gui_entry_erase_to(GUI_ENTRY_REC *entry, int pos, CUTBUFFER_UPDATE_OP update_cutbuffer);
void gui_entry_erase(GUI_ENTRY_REC *entry, int size, CUTBUFFER_UPDATE_OP update_cutbuffer);
void gui_entry_erase_cell(GUI_ENTRY_REC *entry);
void gui_entry_erase_word(GUI_ENTRY_REC *entry, int to_space, CUTBUFFER_UPDATE_OP cutbuffer_op);
void gui_entry_erase_next_word(GUI_ENTRY_REC *entry, int to_space, CUTBUFFER_UPDATE_OP cutbuffer_op);

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

void gui_entry_set_extent(GUI_ENTRY_REC *entry, int pos, const char *text);
void gui_entry_set_extents(GUI_ENTRY_REC *entry, int pos, int len, const char *left, const char *right);
void gui_entry_clear_extents(GUI_ENTRY_REC *entry, int pos, int len);
char *gui_entry_get_extent(GUI_ENTRY_REC *entry, int pos);
GSList *gui_entry_get_text_and_extents(GUI_ENTRY_REC *entry);
void gui_entry_set_text_and_extents(GUI_ENTRY_REC *entry, GSList *list);

void gui_entry_init(void);
void gui_entry_deinit(void);

#endif
