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
#include "servers.h"
#include "misc.h"
#include "settings.h"

#include "completion.h"
#include "command-history.h"
#include "keyboard.h"
#include "translation.h"
#include "fe-windows.h"

#include "screen.h"
#include "gui-entry.h"
#include "gui-windows.h"

#include <signal.h>

#undef CTRL
#define CTRL(x) ((x) & 0x1f)	/* Ctrl+x */

typedef void (*ENTRY_REDIRECT_KEY_FUNC) (int key, void *data, SERVER_REC *server, WI_ITEM_REC *item);
typedef void (*ENTRY_REDIRECT_ENTRY_FUNC) (const char *line, void *data, SERVER_REC *server, WI_ITEM_REC *item);

typedef struct {
	SIGNAL_FUNC func;
        int key;
	void *data;
} ENTRY_REDIRECT_REC;

static ENTRY_REDIRECT_REC *redir;

char *cutbuffer;
static int readtag, sigint_count = 0;
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
	window_update_prompt(active_win);
}

static void handle_entry_redirect(const char *line)
{
	ENTRY_REDIRECT_ENTRY_FUNC func;
	void *data;

	func = (ENTRY_REDIRECT_ENTRY_FUNC) redir->func;
	data = redir->data;
	g_free_and_null(redir);

	if (func != NULL)
		func(line, data, active_win->active_server, active_win->active);

	gui_entry_remove_perm_prompt();
	window_update_prompt(active_win);
}

static int get_scroll_count(void)
{
	const char *str;
	int count;

	str = settings_get_str("scroll_page_count");
	count = atoi(str + (*str == '/'));
	if (count < 0) count = 1;
	
	if (*str == '/')
		count = WINDOW_GUI(active_win)->parent->lines/count;
	return count;
}

static void window_prev_page(void)
{
	gui_window_scroll(active_win, -get_scroll_count());
}

static void window_next_page(void)
{
	gui_window_scroll(active_win, get_scroll_count());
}

static const char *get_key_name(int key)
{
	switch (key) {
	case 8:
	case 127:
	case KEY_BACKSPACE:
		return "Backspace";
	case 9:
		return "Tab";
	case KEY_HOME:
		return "Home";
#ifdef KEY_END
	case KEY_END:
#endif
#ifdef KEY_LL
	case KEY_LL:
#endif
#if defined (KEY_END) || defined (KEY_LL)
		return "End";
#endif
	case KEY_PPAGE:
		return "Prior";
	case KEY_NPAGE:
		return "Next";
	case KEY_UP:
		return "Up";
	case KEY_DOWN:
		return "Down";
	case KEY_LEFT:
		return "Left";
	case KEY_RIGHT:
		return "Right";
	case KEY_DC:
		return "Delete";
	case KEY_IC:
		return "Insert";
	case '\n':
	case 13:
		return "Return";
	default:
		return NULL;
	}
}

void handle_key(int key)
{
        const char *keyname;
	char *str;

	/* Quit if we get 5 CTRL-C's in a row. */
	if (key != CTRL('c'))
		sigint_count = 0;
	else if (++sigint_count >= 5)
		raise(SIGTERM);

	idle_time = time(NULL);

	if (redir != NULL && redir->key) {
		handle_key_redirect(key);
		return;
	}

	switch (key)
	{
	case 27:
		key = getch();
		if (key == 'O') {
			key = getch();
			switch (key) {
			case 'a':
                                str = g_strdup("CTRL-Up");
				break;
			case 'b':
                                str = g_strdup("CTRL-Down");
				break;
			case 'c':
                                str = g_strdup("CTRL-Right");
                                break;
			case 'd':
                                str = g_strdup("CTRL-Left");
				break;
			default:
				return;
			}
		} else if (key == toupper(key) && key != tolower(key))
			str = g_strdup_printf("ALT-SHIFT-%c", key);
		else {
			keyname = get_key_name(key);
			if (keyname != NULL)
				str = g_strdup_printf("ALT-%s", keyname);
			else if (key >= 32 && key < 256 && key != 128)
				str = g_strdup_printf("ALT-%c", toupper(key));
			else {
				str = g_strdup_printf("ALT-%d", key);
			}
		}
		key_pressed(str, NULL);
		g_free(str);
		break;
	case '\n':
	case 13:
		key_pressed("Return", NULL);

		str = gui_entry_get_text();
		if (*str == '\0') break;

		translate_output(str);

		if (redir == NULL)
			signal_emit("send command", 3, str, active_win->active_server, active_win->active);
		else
			handle_entry_redirect(str);

		command_history_add(active_win, gui_entry_get_text(), FALSE);
		gui_entry_set_text("");
		command_history_clear_pos(active_win);
		break;

	default:
                keyname = get_key_name(key);
		if (keyname != NULL) {
			key_pressed(keyname, NULL);
			break;
		}
		if (key >= 0 && key < 32) {
			str = g_strdup_printf("CTRL-%c",
					      key == 0 ? ' ' :
					      (key == 31 ? '-' : key+'A'-1));
			key_pressed(str, NULL);
			g_free(str);
			break;
		}

		if (key < 256) {
			char str[2];

			str[0] = toupper(key); str[1] = '\0';
			key_pressed(str, NULL);
			gui_entry_insert_char((char) key);
		}
		break;
	}
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
	if (gui_entry_get_pos() < strlen(gui_entry_get_text())) {
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
	/* FIXME */
}

static void key_delete_next_word(void)
{
	/* FIXME */
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
		if (key == ERR) break;

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
	signal_emit("command window prev", 3, "", active_win->active_server, active_win->active);
}

static void key_next_window(void)
{
	signal_emit("command window next", 3, "", active_win->active_server, active_win->active);
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

	if (active_win->items != NULL)
		signal_emit("command window item next", 3, "", active_win->active_server, active_win->active);
	else if (servers != NULL) {
		/* change server */
		if (active_win->active_server == NULL)
			server = servers->data;
		else {
			index = g_slist_index(servers, active_win->active_server);
			server = index > 0 ? g_slist_nth(servers, index-1)->data :
				g_slist_last(servers)->data;
		}
		signal_emit("command window server", 3, server->tag, active_win->active_server, active_win->active);
	}
}

static void key_addchar(const char *data)
{
	gui_entry_insert_char(*data);
}

static void sig_window_auto_changed(void)
{
	command_history_next(active_win, gui_entry_get_text());
	gui_entry_set_text("");
}

static void sig_gui_entry_redirect(SIGNAL_FUNC func, const char *entry, gpointer key, void *data)
{
	redir = g_new0(ENTRY_REDIRECT_REC, 1);
	redir->func = func;
	redir->key = key != NULL;
	redir->data = data;

	gui_entry_set_perm_prompt(entry);
}

void gui_readline_init(void)
{
	static char changekeys[] = "1234567890QWERTYUIO";
	char *key, data[MAX_INT_STRLEN];
	int n;

	cutbuffer = NULL;
	redir = NULL;
	idle_time = time(NULL);
	readtag = g_input_add_full(g_io_channel_unix_new(0),
				   G_PRIORITY_HIGH, G_INPUT_READ,
				   (GInputFunction) readline, NULL);

	settings_add_str("history", "scroll_page_count", "/2");

	key_bind("backward_character", "", "Left", NULL, (SIGNAL_FUNC) key_backward_character);
	key_bind("forward_character", "", "Right", NULL, (SIGNAL_FUNC) key_forward_character);
 	key_bind("backward_word", "", "Ctrl-Left", NULL, (SIGNAL_FUNC) key_backward_word);
	key_bind("forward_word", "", "Ctrl-Right", NULL, (SIGNAL_FUNC) key_forward_word);
	key_bind("beginning_of_line", "", "Home", NULL, (SIGNAL_FUNC) key_beginning_of_line);
	key_bind("beginning_of_line", NULL, "Ctrl-A", NULL, (SIGNAL_FUNC) key_beginning_of_line);
	key_bind("end_of_line", "", "End", NULL, (SIGNAL_FUNC) key_end_of_line);
	key_bind("end_of_line", NULL, "Ctrl-E", NULL, (SIGNAL_FUNC) key_end_of_line);

	key_bind("backward_history", "", "Up", NULL, (SIGNAL_FUNC) key_backward_history);
	key_bind("forward_history", "", "Down", NULL, (SIGNAL_FUNC) key_forward_history);

	key_bind("backspace", "", "Backspace", NULL, (SIGNAL_FUNC) key_backspace);
	key_bind("delete_character", "", "Delete", NULL, (SIGNAL_FUNC) key_delete_character);
	key_bind("delete_character", NULL, "Ctrl-D", NULL, (SIGNAL_FUNC) key_delete_character);
	key_bind("delete_next_word", "", NULL, NULL, (SIGNAL_FUNC) key_delete_next_word);
	key_bind("delete_previous_word", "", NULL, NULL, (SIGNAL_FUNC) key_delete_previous_word);
	key_bind("delete_to_previous_space", "", "Ctrl-W", NULL, (SIGNAL_FUNC) key_delete_to_previous_space);
	key_bind("erase_line", "", "Ctrl-U", NULL, (SIGNAL_FUNC) key_erase_line);
	key_bind("erase_to_beg_of_line", "", NULL, NULL, (SIGNAL_FUNC) key_erase_to_beg_of_line);
	key_bind("erase_to_end_of_line", "", "Ctrl-K", NULL, (SIGNAL_FUNC) key_erase_to_end_of_line);
	key_bind("yank_from_cutbuffer", "", "Ctrl-Y", NULL, (SIGNAL_FUNC) key_yank_from_cutbuffer);
	key_bind("transpose_characters", "", "Ctrl-T", NULL, (SIGNAL_FUNC) key_transpose_characters);
        
	key_bind("word_completion", "", "Tab", NULL, (SIGNAL_FUNC) key_word_completion);
	key_bind("check_replaces", "Check word replaces", " ", NULL, (SIGNAL_FUNC) key_check_replaces);
	key_bind("check_replaces", NULL, "Return", NULL, (SIGNAL_FUNC) key_check_replaces);

	key_bind("previous_window", "Previous window", "CTRL-P", NULL, (SIGNAL_FUNC) key_previous_window);
	key_bind("previous_window", NULL, "ALT-Left", NULL, (SIGNAL_FUNC) key_previous_window);
	key_bind("next_window", "Next window", "CTRL-N", NULL, (SIGNAL_FUNC) key_next_window);
	key_bind("next_window", NULL, "ALT-Right", NULL, (SIGNAL_FUNC) key_next_window);
	key_bind("upper_window", "Upper window", "ALT-Up", NULL, (SIGNAL_FUNC) key_upper_window);
	key_bind("lower_window", "Lower window", "ALT-Down", NULL, (SIGNAL_FUNC) key_lower_window);
	key_bind("active_window", "Go to next window with the highest activity", "ALT-A", NULL, (SIGNAL_FUNC) key_active_window);
	key_bind("next_window_item", "Next channel/query", "CTRL-X", NULL, (SIGNAL_FUNC) key_next_window_item);
	key_bind("previous_window_item", "Previous channel/query", NULL, NULL, (SIGNAL_FUNC) key_previous_window_item);

	key_bind("refresh_screen", "Redraw screen", "CTRL-L", NULL, (SIGNAL_FUNC) irssi_redraw);
	key_bind("scroll_backward", "Previous page", "Prior", NULL, (SIGNAL_FUNC) key_scroll_backward);
	key_bind("scroll_backward", NULL, "ALT-P", NULL, (SIGNAL_FUNC) key_scroll_backward);
	key_bind("scroll_forward", "Next page", "Next", NULL, (SIGNAL_FUNC) key_scroll_forward);
	key_bind("scroll_forward", NULL, "ALT-N", NULL, (SIGNAL_FUNC) key_scroll_forward);
	key_bind("scroll_start", "Beginning of the window", "", NULL, (SIGNAL_FUNC) key_scroll_start);
	key_bind("scroll_end", "End of the window", "", NULL, (SIGNAL_FUNC) key_scroll_end);

	key_bind("special_char", "Insert special character", "CTRL-B", "\002", (SIGNAL_FUNC) key_addchar);
	key_bind("special_char", NULL, "CTRL--", "\037", (SIGNAL_FUNC) key_addchar);
	key_bind("special_char", NULL, "CTRL-C", "\003", (SIGNAL_FUNC) key_addchar);
	key_bind("special_char", NULL, "CTRL-V", "\026", (SIGNAL_FUNC) key_addchar);
	key_bind("special_char", NULL, "CTRL-G", "\007", (SIGNAL_FUNC) key_addchar);
	key_bind("special_char", NULL, "CTRL-O", "\017", (SIGNAL_FUNC) key_addchar);

	for (n = 0; changekeys[n] != '\0'; n++) {
		key = g_strdup_printf("ALT-%c", changekeys[n]);
		ltoa(data, n+1);
		key_bind("change_window", "Change window", key, data, (SIGNAL_FUNC) key_change_window);
		g_free(key);
	}

	signal_add("window changed automatic", (SIGNAL_FUNC) sig_window_auto_changed);
	signal_add("gui entry redirect", (SIGNAL_FUNC) sig_gui_entry_redirect);
}

void gui_readline_deinit(void)
{
	g_free_not_null(cutbuffer);
	g_source_remove(readtag);

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

	key_unbind("special_char", (SIGNAL_FUNC) key_addchar);
	key_unbind("change_window", (SIGNAL_FUNC) key_change_window);

	signal_remove("window changed automatic", (SIGNAL_FUNC) sig_window_auto_changed);
	signal_remove("gui entry redirect", (SIGNAL_FUNC) sig_gui_entry_redirect);
}
