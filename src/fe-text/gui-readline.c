/*
 gui-readline.c : irssi

    Copyright (C) 1999 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"
#include "special-vars.h"

#include "completion.h"
#include "command-history.h"
#include "keyboard.h"
#include "translation.h"

#include "screen.h"
#include "gui-entry.h"
#include "gui-windows.h"

#include <signal.h>

typedef void (*ENTRY_REDIRECT_KEY_FUNC) (int key, void *data, SERVER_REC *server, WI_ITEM_REC *item);
typedef void (*ENTRY_REDIRECT_ENTRY_FUNC) (const char *line, void *data, SERVER_REC *server, WI_ITEM_REC *item);

typedef struct {
	SIGNAL_FUNC func;
        int flags;
	void *data;
} ENTRY_REDIRECT_REC;

static KEYBOARD_REC *keyboard;
static ENTRY_REDIRECT_REC *redir;

char *cutbuffer;
static int readtag;
static time_t idle_time;

static void handle_key_redirect(int key)
{
	ENTRY_REDIRECT_KEY_FUNC func;
	void *data;

	func = (ENTRY_REDIRECT_KEY_FUNC) redir->func;
	data = redir->data;
	g_free_and_null(redir);

	if (func != NULL)
		func(key, data, active_win->active_server, active_win->active);

	gui_entry_remove_perm_prompt();
	window_update_prompt();
}

static void handle_entry_redirect(const char *line)
{
	ENTRY_REDIRECT_ENTRY_FUNC func;
	void *data;

        gui_entry_set_hidden(FALSE);

	func = (ENTRY_REDIRECT_ENTRY_FUNC) redir->func;
	data = redir->data;
	g_free_and_null(redir);

	if (func != NULL) {
		func(line, data, active_win->active_server,
		     active_win->active);
	}

	gui_entry_remove_perm_prompt();
	window_update_prompt();
}

static int get_scroll_count(void)
{
	const char *str;
	double count;

	str = settings_get_str("scroll_page_count");
	count = atof(str + (*str == '/'));
	if (count <= 0)
		count = 1;
	else if (count < 1)
                count = 1.0/count;

	if (*str == '/')
		count = WINDOW_GUI(active_win)->parent->height/count;
	return (int)count;
}

static void window_prev_page(void)
{
	gui_window_scroll(active_win, -get_scroll_count());
}

static void window_next_page(void)
{
	gui_window_scroll(active_win, get_scroll_count());
}

void handle_key(int key)
{
	char str[3];

	idle_time = time(NULL);

	if (redir != NULL && redir->flags & ENTRY_REDIRECT_FLAG_HOTKEY) {
		handle_key_redirect(key);
		return;
	}

	if (key >= 0 && key < 32) {
		/* control key */
                str[0] = '^';
		str[1] = key+'@';
                str[2] = '\0';
	} else if (key == 127) {
                str[0] = '^';
		str[1] = '?';
                str[2] = '\0';
	} else {
		str[0] = key;
		str[1] = '\0';
	}

	if (!key_pressed(keyboard, str)) {
                /* key wasn't used for anything, print it */
		gui_entry_insert_char((char) key);
	}
}

static void key_send_line(void)
{
	int add_history;
        char *str;

	str = gui_entry_get_text();
	if (*str == '\0') return;

	translate_output(str);

	add_history = TRUE;
	if (redir == NULL) {
		signal_emit("send command", 3, str,
			    active_win->active_server,
			    active_win->active);
	} else {
		if (redir->flags & ENTRY_REDIRECT_FLAG_HIDDEN)
			add_history = FALSE;
		handle_entry_redirect(str);
	}

	if (add_history) {
		command_history_add(active_win, gui_entry_get_text(),
				    FALSE);
	}
	gui_entry_set_text("");
	command_history_clear_pos(active_win);
}

static void key_combo(void)
{
}

static void key_backward_history(void)
{
	const char *text;

	text = command_history_prev(active_win, gui_entry_get_text());
	gui_entry_set_text(text);
}

static void key_forward_history(void)
{
	const char *text;

	text = command_history_next(active_win, gui_entry_get_text());
	gui_entry_set_text(text);
}

static void key_beginning_of_line(void)
{
        gui_entry_set_pos(0);
}

static void key_end_of_line(void)
{
	gui_entry_set_pos(strlen(gui_entry_get_text()));
}

static void key_backward_character(void)
{
	gui_entry_move_pos(-1);
}

static void key_forward_character(void)
{
	gui_entry_move_pos(1);
}

static void key_backward_word(void)
{
	gui_entry_move_words(-1);
}

static void key_forward_word(void)
{
	gui_entry_move_words(1);
}

static void key_erase_line(void)
{
	g_free_not_null(cutbuffer);
	cutbuffer = g_strdup(gui_entry_get_text());

	gui_entry_set_text("");
}

static void key_erase_to_beg_of_line(void)
{
	int pos;

	pos = gui_entry_get_pos();
	g_free_not_null(cutbuffer);
	cutbuffer = g_strndup(gui_entry_get_text(), pos);

	gui_entry_erase(pos);
}

static void key_erase_to_end_of_line(void)
{
	int pos;

	pos = gui_entry_get_pos();
	g_free_not_null(cutbuffer);
	cutbuffer = g_strdup(gui_entry_get_text()+pos);

	gui_entry_set_pos(strlen(gui_entry_get_text()));
	gui_entry_erase(strlen(gui_entry_get_text()) - pos);
}

static void key_yank_from_cutbuffer(void)
{
	if (cutbuffer != NULL)
		gui_entry_insert_text(cutbuffer);
}

static void key_transpose_characters(void)
{
	char *line, c;
	int pos;

	pos = gui_entry_get_pos();
	line = gui_entry_get_text();
	if (pos == 0 || strlen(line) < 2)
		return;

	if (line[pos] != '\0')
		gui_entry_move_pos(1);
	c = line[gui_entry_get_pos()-1];
        gui_entry_erase(1);
	gui_entry_move_pos(-1);
	gui_entry_insert_char(c);
        gui_entry_set_pos(pos);
}

static void key_delete_character(void)
{
	if (gui_entry_get_pos() < (int)strlen(gui_entry_get_text())) {
		gui_entry_move_pos(1);
		gui_entry_erase(1);
	}
}

static void key_backspace(void)
{
	gui_entry_erase(1);
}

static void key_delete_previous_word(void)
{
  gui_entry_erase_word();
}

static void key_delete_next_word(void)
{
	gui_entry_erase_next_word();
}

static void key_delete_to_previous_space(void)
{
	gui_entry_erase_word();
}

void readline(void)
{
	int key;

	for (;;) {
		key = getch();
		if (key == ERR
#ifdef KEY_RESIZE
		    || key == KEY_RESIZE
#endif
		   ) break;

		handle_key(key);
	}
}

time_t get_idle_time(void)
{
	return idle_time;
}

static void key_scroll_backward(void)
{
	window_prev_page();
}

static void key_scroll_forward(void)
{
	window_next_page();
}

static void key_scroll_start(void)
{
	signal_emit("command scrollback home", 3, NULL, active_win->active_server, active_win->active);
}

static void key_scroll_end(void)
{
	signal_emit("command scrollback end", 3, NULL, active_win->active_server, active_win->active);
}

static void key_change_window(const char *data)
{
	signal_emit("command window goto", 3, data, active_win->active_server, active_win->active);
}

static void key_word_completion(void)
{
	char *line;
	int pos;

	pos = gui_entry_get_pos();

	line = word_complete(active_win, gui_entry_get_text(), &pos);
	if (line != NULL) {
		gui_entry_set_text(line);
		gui_entry_set_pos(pos);
		g_free(line);
	}
}

static void key_check_replaces(void)
{
	char *line;
	int pos;

	pos = gui_entry_get_pos();

	line = auto_word_complete(gui_entry_get_text(), &pos);
	if (line != NULL) {
		gui_entry_set_text(line);
		gui_entry_set_pos(pos);
		g_free(line);
	}
}

static void key_previous_window(void)
{
	signal_emit("command window previous", 3, "", active_win->active_server, active_win->active);
}

static void key_next_window(void)
{
	signal_emit("command window next", 3, "", active_win->active_server, active_win->active);
}

static void key_left_window(void)
{
	signal_emit("command window left", 3, "", active_win->active_server, active_win->active);
}

static void key_right_window(void)
{
	signal_emit("command window right", 3, "", active_win->active_server, active_win->active);
}

static void key_upper_window(void)
{
	signal_emit("command window up", 3, "", active_win->active_server, active_win->active);
}

static void key_lower_window(void)
{
	signal_emit("command window down", 3, "", active_win->active_server, active_win->active);
}

static void key_active_window(void)
{
	signal_emit("command window goto", 3, "active", active_win->active_server, active_win->active);
}

static void key_previous_window_item(void)
{
	SERVER_REC *server;
	GSList *pos;

	if (active_win->items != NULL)
		signal_emit("command window item prev", 3, "", active_win->active_server, active_win->active);
	else if (servers != NULL) {
		/* change server */
		if (active_win->active_server == NULL)
			server = servers->data;
		else {
			pos = g_slist_find(servers, active_win->active_server);
			server = pos->next != NULL ? pos->next->data : servers->data;
		}
		signal_emit("command window server", 3, server->tag, active_win->active_server, active_win->active);
	}
}

static void key_next_window_item(void)
{
	SERVER_REC *server;
	int index;

	if (active_win->items != NULL) {
		signal_emit("command window item next", 3, "",
			    active_win->active_server, active_win->active);
	}
	else if (servers != NULL) {
		/* change server */
		if (active_win->active_server == NULL)
			server = servers->data;
		else {
			index = g_slist_index(servers, active_win->active_server);
			server = index > 0 ? g_slist_nth(servers, index-1)->data :
				g_slist_last(servers)->data;
		}
		signal_emit("command window server", 3, server->tag,
			    active_win->active_server, active_win->active);
	}
}

static void key_insert_text(const char *data)
{
	char *str;

	str = parse_special_string(data, active_win->active_server,
				   active_win->active, "", NULL, 0);
	gui_entry_insert_text(str);
        g_free(str);
}

static void sig_window_auto_changed(void)
{
	command_history_next(active_win, gui_entry_get_text());
	gui_entry_set_text("");
}

static void sig_gui_entry_redirect(SIGNAL_FUNC func, const char *entry,
				   void *flags, void *data)
{
	redir = g_new0(ENTRY_REDIRECT_REC, 1);
	redir->func = func;
	redir->flags = GPOINTER_TO_INT(flags);
	redir->data = data;

	if (redir->flags & ENTRY_REDIRECT_FLAG_HIDDEN)
		gui_entry_set_hidden(TRUE);
	gui_entry_set_perm_prompt(entry);
}

void gui_readline_init(void)
{
	static char changekeys[] = "1234567890qwertyuio";
	char *key, data[MAX_INT_STRLEN];
	int n;

	cutbuffer = NULL;
	redir = NULL;
	idle_time = time(NULL);
	readtag = g_input_add_full(g_io_channel_unix_new(0),
				   G_PRIORITY_HIGH, G_INPUT_READ,
				   (GInputFunction) readline, NULL);

	settings_add_str("history", "scroll_page_count", "/2");

	keyboard = keyboard_create(NULL);
        key_configure_freeze();

	key_bind("key", NULL, "^M", "return", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "^J", "return", (SIGNAL_FUNC) key_combo);

        /* meta */
	key_bind("key", NULL, "^[", "meta", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-[", "meta2", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-O", "meta2", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-[O", "meta2", (SIGNAL_FUNC) key_combo);

        /* arrow keys */
	key_bind("key", NULL, "meta2-A", "up", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-B", "down", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-C", "right", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-D", "left", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-1~", "home", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-7~", "home", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-H", "home", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-4~", "end", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-8~", "end", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-F", "end", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-5~", "prior", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-I", "prior", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-6~", "next", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-G", "next", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-2~", "insert", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-3~", "delete", (SIGNAL_FUNC) key_combo);

        /* cursor movement */
	key_bind("backward_character", "", "left", NULL, (SIGNAL_FUNC) key_backward_character);
	key_bind("forward_character", "", "right", NULL, (SIGNAL_FUNC) key_forward_character);
 	key_bind("backward_word", "", "meta2-d", NULL, (SIGNAL_FUNC) key_backward_word);
	key_bind("forward_word", "", "meta2-c", NULL, (SIGNAL_FUNC) key_forward_word);
	key_bind("beginning_of_line", "", "home", NULL, (SIGNAL_FUNC) key_beginning_of_line);
	key_bind("beginning_of_line", NULL, "^A", NULL, (SIGNAL_FUNC) key_beginning_of_line);
	key_bind("end_of_line", "", "end", NULL, (SIGNAL_FUNC) key_end_of_line);
	key_bind("end_of_line", NULL, "^E", NULL, (SIGNAL_FUNC) key_end_of_line);

        /* history */
	key_bind("backward_history", "", "up", NULL, (SIGNAL_FUNC) key_backward_history);
	key_bind("forward_history", "", "down", NULL, (SIGNAL_FUNC) key_forward_history);

        /* line editing */
	key_bind("backspace", "", "^H", NULL, (SIGNAL_FUNC) key_backspace);
	key_bind("backspace", "", "^?", NULL, (SIGNAL_FUNC) key_backspace);
	key_bind("delete_character", "", "delete", NULL, (SIGNAL_FUNC) key_delete_character);
	key_bind("delete_character", NULL, "^D", NULL, (SIGNAL_FUNC) key_delete_character);
	key_bind("delete_next_word", "", NULL, NULL, (SIGNAL_FUNC) key_delete_next_word);
	key_bind("delete_previous_word", "", NULL, NULL, (SIGNAL_FUNC) key_delete_previous_word);
	key_bind("delete_to_previous_space", "", "^W", NULL, (SIGNAL_FUNC) key_delete_to_previous_space);
	key_bind("erase_line", "", "^U", NULL, (SIGNAL_FUNC) key_erase_line);
	key_bind("erase_to_beg_of_line", "", NULL, NULL, (SIGNAL_FUNC) key_erase_to_beg_of_line);
	key_bind("erase_to_end_of_line", "", "^K", NULL, (SIGNAL_FUNC) key_erase_to_end_of_line);
	key_bind("yank_from_cutbuffer", "", "^Y", NULL, (SIGNAL_FUNC) key_yank_from_cutbuffer);
	key_bind("transpose_characters", "Swap current and previous character", "^T", NULL, (SIGNAL_FUNC) key_transpose_characters);

        /* line transmitting */
	key_bind("send_line", "Execute the input line", "return", NULL, (SIGNAL_FUNC) key_send_line);
	key_bind("word_completion", "", "^I", NULL, (SIGNAL_FUNC) key_word_completion);
	key_bind("check_replaces", "Check word replaces", " ", NULL, (SIGNAL_FUNC) key_check_replaces);
	key_bind("check_replaces", NULL, NULL, NULL, (SIGNAL_FUNC) key_check_replaces);

        /* window managing */
	key_bind("previous_window", "Previous window", "^P", NULL, (SIGNAL_FUNC) key_previous_window);
	key_bind("left_window", "Window in left", "meta-left", NULL, (SIGNAL_FUNC) key_left_window);
	key_bind("next_window", "Next window", "^N", NULL, (SIGNAL_FUNC) key_next_window);
	key_bind("right_window", "Window in right", "meta-right", NULL, (SIGNAL_FUNC) key_right_window);
	key_bind("upper_window", "Upper window", "meta-up", NULL, (SIGNAL_FUNC) key_upper_window);
	key_bind("lower_window", "Lower window", "meta-down", NULL, (SIGNAL_FUNC) key_lower_window);
	key_bind("active_window", "Go to next window with the highest activity", "meta-a", NULL, (SIGNAL_FUNC) key_active_window);
	key_bind("next_window_item", "Next channel/query", "^X", NULL, (SIGNAL_FUNC) key_next_window_item);
	key_bind("previous_window_item", "Previous channel/query", NULL, NULL, (SIGNAL_FUNC) key_previous_window_item);

	key_bind("refresh_screen", "Redraw screen", "^L", NULL, (SIGNAL_FUNC) irssi_redraw);
	key_bind("scroll_backward", "Previous page", "prior", NULL, (SIGNAL_FUNC) key_scroll_backward);
	key_bind("scroll_backward", NULL, "meta-p", NULL, (SIGNAL_FUNC) key_scroll_backward);
	key_bind("scroll_forward", "Next page", "next", NULL, (SIGNAL_FUNC) key_scroll_forward);
	key_bind("scroll_forward", NULL, "meta-n", NULL, (SIGNAL_FUNC) key_scroll_forward);
	key_bind("scroll_start", "Beginning of the window", "", NULL, (SIGNAL_FUNC) key_scroll_start);
	key_bind("scroll_end", "End of the window", "", NULL, (SIGNAL_FUNC) key_scroll_end);

        /* inserting special input characters to line.. */
	key_bind("insert_text", "Append text to line", NULL, NULL, (SIGNAL_FUNC) key_insert_text);

	key_bind("multi", NULL, "return", "check_replaces;send_line", NULL);

	for (n = 0; changekeys[n] != '\0'; n++) {
		key = g_strdup_printf("meta-%c", changekeys[n]);
		ltoa(data, n+1);
		key_bind("change_window", "Change window", key, data, (SIGNAL_FUNC) key_change_window);
		g_free(key);
	}

        key_configure_thaw();

	signal_add("window changed automatic", (SIGNAL_FUNC) sig_window_auto_changed);
	signal_add("gui entry redirect", (SIGNAL_FUNC) sig_gui_entry_redirect);
}

void gui_readline_deinit(void)
{
	g_free_not_null(cutbuffer);
	g_source_remove(readtag);

        key_configure_freeze();

	key_unbind("backward_character", (SIGNAL_FUNC) key_backward_character);
	key_unbind("forward_character", (SIGNAL_FUNC) key_forward_character);
 	key_unbind("backward_word", (SIGNAL_FUNC) key_backward_word);
	key_unbind("forward_word", (SIGNAL_FUNC) key_forward_word);
	key_unbind("beginning_of_line", (SIGNAL_FUNC) key_beginning_of_line);
	key_unbind("end_of_line", (SIGNAL_FUNC) key_end_of_line);

	key_unbind("backward_history", (SIGNAL_FUNC) key_backward_history);
	key_unbind("forward_history", (SIGNAL_FUNC) key_forward_history);

	key_unbind("backspace", (SIGNAL_FUNC) key_backspace);
	key_unbind("delete_character", (SIGNAL_FUNC) key_delete_character);
	key_unbind("delete_next_word", (SIGNAL_FUNC) key_delete_next_word);
	key_unbind("delete_previous_word", (SIGNAL_FUNC) key_delete_previous_word);
	key_unbind("delete_to_previous_space", (SIGNAL_FUNC) key_delete_to_previous_space);
	key_unbind("erase_line", (SIGNAL_FUNC) key_erase_line);
	key_unbind("erase_to_beg_of_line", (SIGNAL_FUNC) key_erase_to_beg_of_line);
	key_unbind("erase_to_end_of_line", (SIGNAL_FUNC) key_erase_to_end_of_line);
	key_unbind("yank_from_cutbuffer", (SIGNAL_FUNC) key_yank_from_cutbuffer);
	key_unbind("transpose_characters", (SIGNAL_FUNC) key_transpose_characters);

	key_unbind("word_completion", (SIGNAL_FUNC) key_word_completion);
	key_unbind("check_replaces", (SIGNAL_FUNC) key_check_replaces);

	key_unbind("previous_window", (SIGNAL_FUNC) key_previous_window);
	key_unbind("next_window", (SIGNAL_FUNC) key_next_window);
	key_unbind("upper_window", (SIGNAL_FUNC) key_upper_window);
	key_unbind("lower_window", (SIGNAL_FUNC) key_lower_window);
	key_unbind("active_window", (SIGNAL_FUNC) key_active_window);
	key_unbind("next_window_item", (SIGNAL_FUNC) key_next_window_item);
	key_unbind("previous_window_item", (SIGNAL_FUNC) key_previous_window_item);

	key_unbind("refresh_screen", (SIGNAL_FUNC) irssi_redraw);
	key_unbind("scroll_backward", (SIGNAL_FUNC) key_scroll_backward);
	key_unbind("scroll_forward", (SIGNAL_FUNC) key_scroll_forward);
	key_unbind("scroll_start", (SIGNAL_FUNC) key_scroll_start);
	key_unbind("scroll_end", (SIGNAL_FUNC) key_scroll_end);

	key_unbind("insert_text", (SIGNAL_FUNC) key_insert_text);
	key_unbind("change_window", (SIGNAL_FUNC) key_change_window);
        keyboard_destroy(keyboard);

        key_configure_thaw();

	signal_remove("window changed automatic", (SIGNAL_FUNC) sig_window_auto_changed);
	signal_remove("gui entry redirect", (SIGNAL_FUNC) sig_gui_entry_redirect);
}
