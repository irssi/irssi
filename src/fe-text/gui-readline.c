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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"
#include "special-vars.h"
#include "levels.h"
#include "servers.h"

#include "completion.h"
#include "command-history.h"
#include "keyboard.h"
#include "printtext.h"

#include "term.h"
#include "gui-entry.h"
#include "gui-windows.h"
#include "utf8.h"

#include <string.h>
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
static int escape_next_key;

static int readtag;
static unichar prev_key;
static GTimeVal last_keypress;

static int paste_detect_time, paste_verify_line_count;
static char *paste_entry;
static int paste_entry_pos;
static GArray *paste_buffer;
static GArray *paste_buffer_rest;

static char *paste_old_prompt;
static int paste_prompt, paste_line_count;
static int paste_join_multiline;
static int paste_timeout_id;
static int paste_use_bracketed_mode;
static int paste_bracketed_mode;

/* Terminal sequences that surround the input when the terminal has the
 * bracketed paste mode active. Fror more details see
 * https://cirw.in/blog/bracketed-paste */
static const unichar bp_start[] = { 0x1b, '[', '2', '0', '0', '~' };
static const unichar bp_end[]   = { 0x1b, '[', '2', '0', '1', '~' };

static void sig_input(void);

void input_listen_init(int handle)
{
	readtag = g_input_add_poll(handle,
				   G_PRIORITY_HIGH, G_INPUT_READ,
				   (GInputFunction) sig_input, NULL);
}

void input_listen_deinit(void)
{
	g_source_remove(readtag);
        readtag = -1;
}

static void handle_key_redirect(int key)
{
	ENTRY_REDIRECT_KEY_FUNC func;
	void *data;

	func = (ENTRY_REDIRECT_KEY_FUNC) redir->func;
	data = redir->data;
	g_free_and_null(redir);

	gui_entry_set_prompt(active_entry, "");

	if (func != NULL)
		func(key, data, active_win->active_server, active_win->active);
}

static void handle_entry_redirect(const char *line)
{
	ENTRY_REDIRECT_ENTRY_FUNC func;
	void *data;

        gui_entry_set_hidden(active_entry, FALSE);

	func = (ENTRY_REDIRECT_ENTRY_FUNC) redir->func;
	data = redir->data;
	g_free_and_null(redir);

	gui_entry_set_prompt(active_entry, "");

	if (func != NULL) {
		func(line, data, active_win->active_server,
		     active_win->active);
	}
}

static int get_scroll_count(void)
{
	const char *str;
	double count;

	str = settings_get_str("scroll_page_count");
	count = atof(str + (*str == '/'));
	if (count == 0)
		count = 1;
	else if (count < 0)
		count = active_mainwin->height-active_mainwin->statusbar_lines+count;
	else if (count < 1)
                count = 1.0/count;

	if (*str == '/') {
		count = (active_mainwin->height-active_mainwin->statusbar_lines)/count;
	}
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

static void paste_buffer_join_lines(GArray *buf)
{
#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')
	unsigned int i, count, indent, line_len;
	unichar *arr, *dest, *last_lf_pos;
	int last_lf;

	/* first check if we actually want to join anything. This is assuming
	   that we only want to join lines if

	   a) first line doesn't begin with whitespace
	   b) subsequent lines begin with same amount of whitespace
	   c) whenever there's no whitespace, goto a)

	   For example:

	   line 1
	     line 2
	     line 3
	   line 4
	   line 5
	     line 6

	   ->

	   line1 line2 line 3
	   line4
	   line5 line 6
	*/
	if (buf->len == 0)
		return;

	arr = (unichar *) paste_buffer->data;

	/* first line */
	if (IS_WHITE(arr[0]))
		return;

	/* find the first beginning of indented line */
	for (i = 1; i < buf->len; i++) {
		if (arr[i-1] == '\n' && IS_WHITE(arr[i]))
			break;
	}
	if (i == buf->len)
		return;

	/* get how much indentation we have.. */
	for (indent = 0; i < buf->len; i++, indent++) {
		if (!IS_WHITE(arr[i]))
			break;
	}
	if (i == buf->len)
		return;

	/* now, enforce these to all subsequent lines */
	count = indent; last_lf = TRUE;
	for (; i < buf->len; i++) {
		if (last_lf) {
			if (IS_WHITE(arr[i]))
				count++;
			else {
				last_lf = FALSE;
				if (count != 0 && count != indent)
					return;
				count = 0;
			}
		}
		if (arr[i] == '\n')
			last_lf = TRUE;
	}

	/* all looks fine - now remove the whitespace, but don't let lines
	   get longer than 400 chars */
	dest = arr; last_lf = TRUE; last_lf_pos = NULL; line_len = 0;
	for (i = 0; i < buf->len; i++) {
		if (last_lf && IS_WHITE(arr[i])) {
			/* whitespace, ignore */
		} else if (arr[i] == '\n') {
			if (!last_lf && i+1 != buf->len &&
			    IS_WHITE(arr[i+1])) {
				last_lf_pos = dest;
				*dest++ = ' ';
			} else {
				*dest++ = '\n'; /* double-LF */
				line_len = 0;
				last_lf_pos = NULL;
			}
			last_lf = TRUE;
		} else {
			last_lf = FALSE;
			if (++line_len >= 400 && last_lf_pos != NULL) {
				memmove(last_lf_pos+1, last_lf_pos,
					(dest - last_lf_pos) * sizeof(unichar));
				*last_lf_pos = '\n'; last_lf_pos = NULL;
				line_len = 0;
				dest++;
			}
			*dest++ = arr[i];
		}
	}
	g_array_set_size(buf, dest - arr);
}

static void paste_send(void)
{
	HISTORY_REC *history;
	unichar *arr;
	GString *str;
	char out[10], *text;
	unsigned int i;

	if (paste_join_multiline)
		paste_buffer_join_lines(paste_buffer);

	arr = (unichar *) paste_buffer->data;
	if (active_entry->text_len == 0)
		i = 0;
	else {
		/* first line has to be kludged kind of to get pasting in the
		   middle of line right.. */
		for (i = 0; i < paste_buffer->len; i++) {
			if (arr[i] == '\r' || arr[i] == '\n') {
				i++;
				break;
			}

			gui_entry_insert_char(active_entry, arr[i]);
		}

		text = gui_entry_get_text(active_entry);
		history = command_history_current(active_win);
		command_history_add(history, text);

		signal_emit("send command", 3, text,
			    active_win->active_server, active_win->active);
		g_free(text);
	}

	/* rest of the lines */
	str = g_string_new(NULL);
	for (; i < paste_buffer->len; i++) {
		if (arr[i] == '\r' || arr[i] == '\n') {
			history = command_history_current(active_win);
			command_history_add(history, str->str);

			signal_emit("send command", 3, str->str,
				    active_win->active_server,
				    active_win->active);
			g_string_truncate(str, 0);
		} else if (active_entry->utf8) {
			out[g_unichar_to_utf8(arr[i], out)] = '\0';
			g_string_append(str, out);
		} else if (term_type == TERM_TYPE_BIG5) {
			if (arr[i] > 0xff)
				g_string_append_c(str, (arr[i] >> 8) & 0xff);
			g_string_append_c(str, arr[i] & 0xff);
		} else {
			g_string_append_c(str, arr[i]);
		}
	}

	gui_entry_set_text(active_entry, str->str);
	g_string_free(str, TRUE);
}

static void paste_flush(int send)
{
	if (paste_prompt) {
		gui_entry_set_text(active_entry, paste_entry);
		gui_entry_set_pos(active_entry, paste_entry_pos);
		g_free_and_null(paste_entry);
	}

	if (send)
		paste_send();
	g_array_set_size(paste_buffer, 0);

	/* re-add anything that may have been after the bracketed paste end */
	if (paste_buffer_rest->len) {
		g_array_append_vals(paste_buffer, paste_buffer_rest->data, paste_buffer_rest->len);
		g_array_set_size(paste_buffer_rest, 0);
	}

	gui_entry_set_prompt(active_entry,
			     paste_old_prompt == NULL ? "" : paste_old_prompt);
	g_free(paste_old_prompt); paste_old_prompt = NULL;
	paste_prompt = FALSE;

	paste_line_count = 0;

	gui_entry_redraw(active_entry);
}

static void insert_paste_prompt(void)
{
	char *str;

	paste_prompt = TRUE;
	paste_old_prompt = g_strdup(active_entry->prompt);
	printformat_window(active_win, MSGLEVEL_CLIENTNOTICE,
			   TXT_PASTE_WARNING,
			   paste_line_count,
			   active_win->active == NULL ? "window" :
			   active_win->active->visible_name);

	str = format_get_text(MODULE_NAME, active_win, NULL, NULL,
			      TXT_PASTE_PROMPT, 0, 0);
	gui_entry_set_prompt(active_entry, str);
	paste_entry = gui_entry_get_text(active_entry);
	paste_entry_pos = gui_entry_get_pos(active_entry);
	gui_entry_set_text(active_entry, "");
	g_free(str);
}

static void sig_gui_key_pressed(gpointer keyp)
{
	GTimeVal now;
        unichar key;
	char str[20];
	int ret;

	key = GPOINTER_TO_INT(keyp);

	if (redir != NULL && redir->flags & ENTRY_REDIRECT_FLAG_HOTKEY) {
		handle_key_redirect(key);
		return;
	}

        g_get_current_time(&now);

	if (key < 32) {
		/* control key */
                str[0] = '^';
		str[1] = (char)key+'@';
                str[2] = '\0';
	} else if (key == 127) {
                str[0] = '^';
		str[1] = '?';
                str[2] = '\0';
	} else if (!active_entry->utf8) {
		if (key <= 0xff) {
			str[0] = (char)key;
			str[1] = '\0';
		} else {
			str[0] = (char) (key >> 8);
			str[1] = (char) (key & 0xff);
			str[2] = '\0';
		}
	} else {
                /* need to convert to utf8 */
		str[g_unichar_to_utf8(key, str)] = '\0';
	}

	if (g_strcmp0(str, "^") == 0) {
		/* change it as ^-, that is an invalid control char */
		str[1] = '-';
		str[2] = '\0';
	}

	if (escape_next_key) {
		escape_next_key = FALSE;
		gui_entry_insert_char(active_entry, key);
		ret = 1;
	} else {
		ret = key_pressed(keyboard, str);
		if (ret < 0) {
			/* key wasn't used for anything, print it */
			gui_entry_insert_char(active_entry, key);
		}
	}

	/* ret = 0 : some key create multiple characters - we're in the middle
	   of one. try to detect the keycombo as a single keypress rather than
	   multiple small onces to avoid incorrect paste detection.

	   don't count repeated keys so paste detection won't go on when
	   you're holding some key down */
	if (ret != 0 && key != prev_key) {
		last_keypress = now;
	}
	prev_key = key;
}

static void key_send_line(void)
{
	HISTORY_REC *history;
	char *str;
	int add_history;

	str = gui_entry_get_text(active_entry);

	/* we can't use gui_entry_get_text() later, since the entry might
	   have been destroyed after we get back */
	add_history = *str != '\0';
	history = command_history_current(active_win);

	if (redir == NULL) {
		signal_emit("send command", 3, str,
			    active_win->active_server,
			    active_win->active);
	} else {
		if (redir->flags & ENTRY_REDIRECT_FLAG_HIDDEN)
                        add_history = 0;
		handle_entry_redirect(str);
	}

	if (add_history) {
		history = command_history_find(history);
		if (history != NULL)
			command_history_add(history, str);
	}

	if (active_entry != NULL)
		gui_entry_set_text(active_entry, "");
	command_history_clear_pos(active_win);

        g_free(str);
}

static void key_combo(void)
{
}

static void key_backward_history(void)
{
	const char *text;
        char *line;

	line = gui_entry_get_text(active_entry);
	text = command_history_prev(active_win, line);
	gui_entry_set_text(active_entry, text);
        g_free(line);
}

static void key_forward_history(void)
{
	const char *text;
	char *line;

	line = gui_entry_get_text(active_entry);
	text = command_history_next(active_win, line);
	gui_entry_set_text(active_entry, text);
        g_free(line);
}

static void key_beginning_of_line(void)
{
        gui_entry_set_pos(active_entry, 0);
}

static void key_end_of_line(void)
{
	gui_entry_set_pos(active_entry, active_entry->text_len);
}

static void key_backward_character(void)
{
	gui_entry_move_pos(active_entry, -1);
}

static void key_forward_character(void)
{
	gui_entry_move_pos(active_entry, 1);
}

static void key_backward_word(void)
{
	gui_entry_move_words(active_entry, -1, FALSE);
}

static void key_forward_word(void)
{
	gui_entry_move_words(active_entry, 1, FALSE);
}

static void key_backward_to_space(void)
{
	gui_entry_move_words(active_entry, -1, TRUE);
}

static void key_forward_to_space(void)
{
	gui_entry_move_words(active_entry, 1, TRUE);
}

static void key_erase_line(void)
{
	gui_entry_set_pos(active_entry, active_entry->text_len);
	gui_entry_erase(active_entry, active_entry->text_len, TRUE);
}

static void key_erase_to_beg_of_line(void)
{
	int pos;

	pos = gui_entry_get_pos(active_entry);
	gui_entry_erase(active_entry, pos, TRUE);
}

static void key_erase_to_end_of_line(void)
{
	int pos;

	pos = gui_entry_get_pos(active_entry);
	gui_entry_set_pos(active_entry, active_entry->text_len);
	gui_entry_erase(active_entry, active_entry->text_len - pos, TRUE);
}

static void key_yank_from_cutbuffer(void)
{
	char *cutbuffer;

        cutbuffer = gui_entry_get_cutbuffer(active_entry);
	if (cutbuffer != NULL) {
		gui_entry_insert_text(active_entry, cutbuffer);
                g_free(cutbuffer);
	}
}

static void key_transpose_characters(void)
{
	gui_entry_transpose_chars(active_entry);
}

static void key_transpose_words(void)
{
	gui_entry_transpose_words(active_entry);
}

static void key_capitalize_word(void)
{
	gui_entry_capitalize_word(active_entry);
}

static void key_downcase_word(void)
{
	gui_entry_downcase_word(active_entry);
}
static void key_upcase_word(void)
{
	gui_entry_upcase_word(active_entry);
}

static void key_delete_character(void)
{
	if (gui_entry_get_pos(active_entry) < active_entry->text_len) {
		gui_entry_erase_cell(active_entry);
	}
}

static void key_backspace(void)
{
	gui_entry_erase(active_entry, 1, FALSE);
}

static void key_delete_previous_word(void)
{
	gui_entry_erase_word(active_entry, FALSE);
}

static void key_delete_next_word(void)
{
	gui_entry_erase_next_word(active_entry, FALSE);
}

static void key_delete_to_previous_space(void)
{
	gui_entry_erase_word(active_entry, TRUE);
}

static void key_delete_to_next_space(void)
{
	gui_entry_erase_next_word(active_entry, TRUE);
}

static gboolean paste_timeout(gpointer data)
{
	if (paste_line_count == 0) {
		int i;

		for (i = 0; i < paste_buffer->len; i++) {
			unichar key = g_array_index(paste_buffer, unichar, i);
			signal_emit("gui key pressed", 1, GINT_TO_POINTER(key));
		}
		g_array_set_size(paste_buffer, 0);
	} else if (paste_verify_line_count > 0 &&
		   paste_line_count >= paste_verify_line_count &&
		   active_win->active != NULL)
		insert_paste_prompt();
	else
		paste_flush(TRUE);
	paste_timeout_id = -1;
	return FALSE;
}

static void paste_bracketed_end(int i, gboolean rest)
{
	/* if there's stuff after the end bracket, save it for later */
	if (rest) {
		unichar *start = ((unichar *) paste_buffer->data) + i + G_N_ELEMENTS(bp_end);
		int len = paste_buffer->len - G_N_ELEMENTS(bp_end);

		g_array_set_size(paste_buffer_rest, 0);
		g_array_append_vals(paste_buffer_rest, start, len);
	}

	/* remove the rest, including the trailing sequence chars */
	g_array_set_size(paste_buffer, i);

	/* decide what to do with the buffer */
	paste_timeout(NULL);

	paste_bracketed_mode = FALSE;
}

static void sig_input(void)
{
	if (!active_entry) {
                /* no active entry yet - wait until we have it */
		return;
	}

	if (paste_prompt) {
		GArray *buffer = g_array_new(FALSE, FALSE, sizeof(unichar));
		int line_count = 0;
		unichar key;
		term_gets(buffer, &line_count);
		key = g_array_index(buffer, unichar, 0);
		/* Either Ctrl-k or Ctrl-c is pressed */
		if (key == 11 || key == 3)
			paste_flush(key == 11);
		g_array_free(buffer, TRUE);
	} else {
		term_gets(paste_buffer, &paste_line_count);

		/* use the bracketed paste mode to detect when the user pastes
		 * some text into the entry */
		if (paste_bracketed_mode) {
			int i;
			int len = paste_buffer->len - G_N_ELEMENTS(bp_end);
			unichar *ptr = (unichar *) paste_buffer->data;

			if (len <= 0) {
				return;
			}

			for (i = 0; i <= len; i++, ptr++) {
				if (ptr[0] == bp_end[0] && !memcmp(ptr, bp_end, sizeof(bp_end))) {
					paste_bracketed_end(i, i != len);
					break;
				}
			}
		}
		else if (paste_detect_time > 0 && paste_buffer->len >= 3) {
			if (paste_timeout_id != -1)
				g_source_remove(paste_timeout_id);
			paste_timeout_id = g_timeout_add(paste_detect_time, paste_timeout, NULL);
		} else if (!paste_bracketed_mode) {
			int i;

			for (i = 0; i < paste_buffer->len; i++) {
				unichar key = g_array_index(paste_buffer, unichar, i);
				signal_emit("gui key pressed", 1, GINT_TO_POINTER(key));

				if (paste_bracketed_mode) {
					/* just enabled by the signal, remove what was processed so far */
					g_array_remove_range(paste_buffer, 0, i + 1);
					return;
				}
			}
			g_array_set_size(paste_buffer, 0);
			paste_line_count = 0;
		}
	}
}

static void key_paste_start(void)
{
	paste_bracketed_mode = TRUE;
}

time_t get_idle_time(void)
{
	return last_keypress.tv_sec;
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

static void key_completion(int erase, int backward)
{
	char *text, *line;
	int pos;

        text = gui_entry_get_text_and_pos(active_entry, &pos);
	line = word_complete(active_win, text, &pos, erase, backward);
	g_free(text);

	if (line != NULL) {
		gui_entry_set_text(active_entry, line);
		gui_entry_set_pos(active_entry, pos);
		g_free(line);
	}
}

static void key_word_completion_backward(void)
{
        key_completion(FALSE, TRUE);
}

static void key_word_completion(void)
{
        key_completion(FALSE, FALSE);
}

static void key_erase_completion(void)
{
        key_completion(TRUE, FALSE);
}

static void key_check_replaces(void)
{
	char *text, *line;
	int pos;

        text = gui_entry_get_text_and_pos(active_entry, &pos);
	line = auto_word_complete(text, &pos);
	g_free(text);

	if (line != NULL) {
		gui_entry_set_text(active_entry, line);
		gui_entry_set_pos(active_entry, pos);
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

static SERVER_REC *get_prev_server(SERVER_REC *current)
{
	int pos;

	if (current == NULL) {
		return servers != NULL ? g_slist_last(servers)->data :
			lookup_servers != NULL ?
			g_slist_last(lookup_servers)->data : NULL;
	}

	/* connect2 -> connect1 -> server2 -> server1 -> connect2 -> .. */

	pos = g_slist_index(servers, current);
	if (pos != -1) {
		if (pos > 0)
			return g_slist_nth(servers, pos-1)->data;
		if (lookup_servers != NULL)
			return g_slist_last(lookup_servers)->data;
		return g_slist_last(servers)->data;
	}

	pos = g_slist_index(lookup_servers, current);
	g_assert(pos >= 0);

	if (pos > 0)
		return g_slist_nth(lookup_servers, pos-1)->data;
	if (servers != NULL)
		return g_slist_last(servers)->data;
	return g_slist_last(lookup_servers)->data;
}

static SERVER_REC *get_next_server(SERVER_REC *current)
{
	GSList *pos;

	if (current == NULL) {
		return servers != NULL ? servers->data :
			lookup_servers != NULL ? lookup_servers->data : NULL;
	}

	/* server1 -> server2 -> connect1 -> connect2 -> server1 -> .. */

	pos = g_slist_find(servers, current);
	if (pos != NULL) {
		if (pos->next != NULL)
			return pos->next->data;
		if (lookup_servers != NULL)
			return lookup_servers->data;
		return servers->data;
	}

	pos = g_slist_find(lookup_servers, current);
	g_assert(pos != NULL);

	if (pos->next != NULL)
		return pos->next->data;
	if (servers != NULL)
		return servers->data;
	return lookup_servers->data;
}

static void key_previous_window_item(void)
{
	SERVER_REC *server;

	if (active_win->items != NULL) {
		signal_emit("command window item prev", 3, "",
			    active_win->active_server, active_win->active);
	} else if (servers != NULL || lookup_servers != NULL) {
		/* change server */
		server = active_win->active_server;
		if (server == NULL)
			server = active_win->connect_server;
		server = get_prev_server(server);
		signal_emit("command window server", 3, server->tag,
			    active_win->active_server, active_win->active);
	}
}

static void key_next_window_item(void)
{
	SERVER_REC *server;

	if (active_win->items != NULL) {
		signal_emit("command window item next", 3, "",
			    active_win->active_server, active_win->active);
	} else if (servers != NULL || lookup_servers != NULL) {
		/* change server */
		server = active_win->active_server;
		if (server == NULL)
			server = active_win->connect_server;
		server = get_next_server(server);
		signal_emit("command window server", 3, server->tag,
			    active_win->active_server, active_win->active);
	}
}

static void key_escape(void)
{
        escape_next_key = TRUE;
}

static void key_insert_text(const char *data)
{
	char *str;

	str = parse_special_string(data, active_win->active_server,
				   active_win->active, "", NULL, 0);
	gui_entry_insert_text(active_entry, str);
        g_free(str);
}

static void key_sig_stop(void)
{
        term_stop();
}

static void sig_window_auto_changed(void)
{
	char *text;

	if (active_entry == NULL)
		return;

        text = gui_entry_get_text(active_entry);
	command_history_next(active_win, text);
	gui_entry_set_text(active_entry, "");
        g_free(text);
}

static void sig_gui_entry_redirect(SIGNAL_FUNC func, const char *entry,
				   void *flags, void *data)
{
	redir = g_new0(ENTRY_REDIRECT_REC, 1);
	redir->func = func;
	redir->flags = GPOINTER_TO_INT(flags);
	redir->data = data;

	if (redir->flags & ENTRY_REDIRECT_FLAG_HIDDEN)
		gui_entry_set_hidden(active_entry, TRUE);
	gui_entry_set_prompt(active_entry, entry);
}

static void setup_changed(void)
{
	paste_detect_time = settings_get_time("paste_detect_time");

	paste_verify_line_count = settings_get_int("paste_verify_line_count");
	paste_join_multiline = settings_get_bool("paste_join_multiline");
	paste_use_bracketed_mode = settings_get_bool("paste_use_bracketed_mode");

	/* Enable the bracketed paste mode on demand */
	term_set_bracketed_paste_mode(paste_use_bracketed_mode);
}

void gui_readline_init(void)
{
	static char changekeys[] = "1234567890qwertyuio";
	char *key, data[MAX_INT_STRLEN];
	int n;

        escape_next_key = FALSE;
	redir = NULL;
	paste_entry = NULL;
	paste_entry_pos = 0;
	paste_buffer = g_array_new(FALSE, FALSE, sizeof(unichar));
	paste_buffer_rest = g_array_new(FALSE, FALSE, sizeof(unichar));
        paste_old_prompt = NULL;
	paste_timeout_id = -1;
	paste_bracketed_mode = FALSE;
	g_get_current_time(&last_keypress);
        input_listen_init(STDIN_FILENO);

	settings_add_str("history", "scroll_page_count", "/2");
	settings_add_time("misc", "paste_detect_time", "5msecs");
	settings_add_bool("misc", "paste_use_bracketed_mode", FALSE);
	/* NOTE: function keys can generate at least 5 characters long
	   keycodes. this must be larger to allow them to work. */
	settings_add_int("misc", "paste_verify_line_count", 5);
	settings_add_bool("misc", "paste_join_multiline", TRUE);
        setup_changed();

	keyboard = keyboard_create(NULL);
        key_configure_freeze();

	key_bind("key", NULL, " ", "space", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "^M", "return", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "^J", "return", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "^H", "backspace", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "^?", "backspace", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "^I", "tab", (SIGNAL_FUNC) key_combo);

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

	key_bind("key", NULL, "meta2-d", "cleft", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-c", "cright", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-5D", "cleft", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-5C", "cright", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;5D", "cleft", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;5C", "cright", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-1;3A", "mup", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;3B", "mdown", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;3D", "mleft", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;3C", "mright", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-up", "mup", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-down", "mdown", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-left", "mleft", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta-right", "mright", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-1;5~", "chome", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-7;5~", "chome", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-5H", "chome", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;5H", "chome", (SIGNAL_FUNC) key_combo);

	key_bind("key", NULL, "meta2-4;5~", "cend", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-8;5~", "cend", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-5F", "cend", (SIGNAL_FUNC) key_combo);
	key_bind("key", NULL, "meta2-1;5F", "cend", (SIGNAL_FUNC) key_combo);

	key_bind("paste_start", "Bracketed paste start", "meta2-200~", "paste_start", (SIGNAL_FUNC) key_paste_start);

	/* cursor movement */
	key_bind("backward_character", "Move the cursor a character backward", "left", NULL, (SIGNAL_FUNC) key_backward_character);
	key_bind("forward_character", "Move the cursor a character forward", "right", NULL, (SIGNAL_FUNC) key_forward_character);
 	key_bind("backward_word", "Move the cursor a word backward", "cleft", NULL, (SIGNAL_FUNC) key_backward_word);
 	key_bind("backward_word", NULL, "meta-b", NULL, (SIGNAL_FUNC) key_backward_word);
	key_bind("forward_word", "Move the cursor a word forward", "cright", NULL, (SIGNAL_FUNC) key_forward_word);
	key_bind("forward_word", NULL, "meta-f", NULL, (SIGNAL_FUNC) key_forward_word);
 	key_bind("backward_to_space", "Move the cursor backward to a space", NULL, NULL, (SIGNAL_FUNC) key_backward_to_space);
	key_bind("forward_to_space", "Move the cursor forward to a space", NULL, NULL, (SIGNAL_FUNC) key_forward_to_space);
	key_bind("beginning_of_line", "Move the cursor to the beginning of the line", "home", NULL, (SIGNAL_FUNC) key_beginning_of_line);
	key_bind("beginning_of_line", NULL, "^A", NULL, (SIGNAL_FUNC) key_beginning_of_line);
	key_bind("end_of_line", "Move the cursor to the end of the line", "end", NULL, (SIGNAL_FUNC) key_end_of_line);
	key_bind("end_of_line", NULL, "^E", NULL, (SIGNAL_FUNC) key_end_of_line);

        /* history */
	key_bind("backward_history", "Go back one line in the history", "up", NULL, (SIGNAL_FUNC) key_backward_history);
	key_bind("forward_history", "Go forward one line in the history", "down", NULL, (SIGNAL_FUNC) key_forward_history);

        /* line editing */
	key_bind("backspace", "Delete the previous character", "backspace", NULL, (SIGNAL_FUNC) key_backspace);
	key_bind("delete_character", "Delete the current character", "delete", NULL, (SIGNAL_FUNC) key_delete_character);
	key_bind("delete_character", NULL, "^D", NULL, (SIGNAL_FUNC) key_delete_character);
	key_bind("delete_next_word", "Delete the word after the cursor", "meta-d", NULL, (SIGNAL_FUNC) key_delete_next_word);
	key_bind("delete_previous_word", "Delete the word before the cursor", "meta-backspace", NULL, (SIGNAL_FUNC) key_delete_previous_word);
	key_bind("delete_to_previous_space", "Delete up to the previous space", "^W", NULL, (SIGNAL_FUNC) key_delete_to_previous_space);
	key_bind("delete_to_next_space", "Delete up to the next space", "", NULL, (SIGNAL_FUNC) key_delete_to_next_space);
	key_bind("erase_line", "Erase the whole input line", "^U", NULL, (SIGNAL_FUNC) key_erase_line);
	key_bind("erase_to_beg_of_line", "Erase everything before the cursor", NULL, NULL, (SIGNAL_FUNC) key_erase_to_beg_of_line);
	key_bind("erase_to_end_of_line", "Erase everything after the cursor", "^K", NULL, (SIGNAL_FUNC) key_erase_to_end_of_line);
	key_bind("yank_from_cutbuffer", "\"Undelete\", paste the last deleted text", "^Y", NULL, (SIGNAL_FUNC) key_yank_from_cutbuffer);
	key_bind("transpose_characters", "Swap current and previous character", "^T", NULL, (SIGNAL_FUNC) key_transpose_characters);
	key_bind("transpose_words", "Swap current and previous word", NULL, NULL, (SIGNAL_FUNC) key_transpose_words);
	key_bind("capitalize_word", "Capitalize the current word", NULL, NULL, (SIGNAL_FUNC) key_capitalize_word);
	key_bind("downcase_word", "Downcase the current word", NULL, NULL, (SIGNAL_FUNC) key_downcase_word);
	key_bind("upcase_word", "Upcase the current word", NULL, NULL, (SIGNAL_FUNC) key_upcase_word);

        /* line transmitting */
	key_bind("send_line", "Execute the input line", "return", NULL, (SIGNAL_FUNC) key_send_line);
	key_bind("word_completion_backward", "", NULL, NULL, (SIGNAL_FUNC) key_word_completion_backward);
	key_bind("word_completion", "Complete the current word", "tab", NULL, (SIGNAL_FUNC) key_word_completion);
	key_bind("erase_completion", "Remove the completion added by word_completion", "meta-k", NULL, (SIGNAL_FUNC) key_erase_completion);
	key_bind("check_replaces", "Check word replaces", NULL, NULL, (SIGNAL_FUNC) key_check_replaces);

        /* window managing */
	key_bind("previous_window", "Go to the previous window", "^P", NULL, (SIGNAL_FUNC) key_previous_window);
	key_bind("next_window", "Go to the next window", "^N", NULL, (SIGNAL_FUNC) key_next_window);
	key_bind("upper_window", "Go to the split window above", "mup", NULL, (SIGNAL_FUNC) key_upper_window);
	key_bind("lower_window", "Go to the split window below", "mdown", NULL, (SIGNAL_FUNC) key_lower_window);
	key_bind("left_window", "Go to the previous window in the current split window", "mleft", NULL, (SIGNAL_FUNC) key_left_window);
	key_bind("right_window", "Go to the next window in the current split window", "mright", NULL, (SIGNAL_FUNC) key_right_window);
	key_bind("active_window", "Go to next window with the highest activity", "meta-a", NULL, (SIGNAL_FUNC) key_active_window);
	key_bind("next_window_item", "Go to the next channel/query. In empty windows change to the next server", "^X", NULL, (SIGNAL_FUNC) key_next_window_item);
	key_bind("previous_window_item", "Go to the previous channel/query. In empty windows change to the previous server", NULL, NULL, (SIGNAL_FUNC) key_previous_window_item);

	key_bind("refresh_screen", "Redraw screen", "^L", NULL, (SIGNAL_FUNC) irssi_redraw);
	key_bind("scroll_backward", "Scroll to previous page", "prior", NULL, (SIGNAL_FUNC) key_scroll_backward);
	key_bind("scroll_backward", NULL, "meta-p", NULL, (SIGNAL_FUNC) key_scroll_backward);
	key_bind("scroll_forward", "Scroll to next page", "next", NULL, (SIGNAL_FUNC) key_scroll_forward);
	key_bind("scroll_forward", NULL, "meta-n", NULL, (SIGNAL_FUNC) key_scroll_forward);
	key_bind("scroll_start", "Scroll to the beginning of the window", "chome", NULL, (SIGNAL_FUNC) key_scroll_start);
	key_bind("scroll_end", "Scroll to the end of the window", "cend", NULL, (SIGNAL_FUNC) key_scroll_end);

        /* inserting special input characters to line.. */
	key_bind("escape_char", "Insert the next character exactly as-is to input line", NULL, NULL, (SIGNAL_FUNC) key_escape);
	key_bind("insert_text", "Append text to line", NULL, NULL, (SIGNAL_FUNC) key_insert_text);

        /* autoreplaces */
	key_bind("multi", NULL, "return", "check_replaces;send_line", NULL);
	key_bind("multi", NULL, "space", "check_replaces;insert_text  ", NULL);

        /* moving between windows */
	for (n = 0; changekeys[n] != '\0'; n++) {
		key = g_strdup_printf("meta-%c", changekeys[n]);
		ltoa(data, n+1);
		key_bind("change_window", "Change window", key, data, (SIGNAL_FUNC) key_change_window);
		g_free(key);
	}

        /* misc */
	key_bind("stop_irc", "Send SIGSTOP to client", "^Z", NULL, (SIGNAL_FUNC) key_sig_stop);

        key_configure_thaw();

	signal_add("window changed automatic", (SIGNAL_FUNC) sig_window_auto_changed);
	signal_add("gui entry redirect", (SIGNAL_FUNC) sig_gui_entry_redirect);
	signal_add("gui key pressed", (SIGNAL_FUNC) sig_gui_key_pressed);
	signal_add("setup changed", (SIGNAL_FUNC) setup_changed);
}

void gui_readline_deinit(void)
{
        input_listen_deinit();

        key_configure_freeze();

	key_unbind("paste_start", (SIGNAL_FUNC) key_paste_start);

	key_unbind("backward_character", (SIGNAL_FUNC) key_backward_character);
	key_unbind("forward_character", (SIGNAL_FUNC) key_forward_character);
 	key_unbind("backward_word", (SIGNAL_FUNC) key_backward_word);
	key_unbind("forward_word", (SIGNAL_FUNC) key_forward_word);
 	key_unbind("backward_to_space", (SIGNAL_FUNC) key_backward_to_space);
	key_unbind("forward_to_space", (SIGNAL_FUNC) key_forward_to_space);
	key_unbind("beginning_of_line", (SIGNAL_FUNC) key_beginning_of_line);
	key_unbind("end_of_line", (SIGNAL_FUNC) key_end_of_line);

	key_unbind("backward_history", (SIGNAL_FUNC) key_backward_history);
	key_unbind("forward_history", (SIGNAL_FUNC) key_forward_history);

	key_unbind("backspace", (SIGNAL_FUNC) key_backspace);
	key_unbind("delete_character", (SIGNAL_FUNC) key_delete_character);
	key_unbind("delete_next_word", (SIGNAL_FUNC) key_delete_next_word);
	key_unbind("delete_previous_word", (SIGNAL_FUNC) key_delete_previous_word);
	key_unbind("delete_to_next_space", (SIGNAL_FUNC) key_delete_to_next_space);
	key_unbind("delete_to_previous_space", (SIGNAL_FUNC) key_delete_to_previous_space);
	key_unbind("erase_line", (SIGNAL_FUNC) key_erase_line);
	key_unbind("erase_to_beg_of_line", (SIGNAL_FUNC) key_erase_to_beg_of_line);
	key_unbind("erase_to_end_of_line", (SIGNAL_FUNC) key_erase_to_end_of_line);
	key_unbind("yank_from_cutbuffer", (SIGNAL_FUNC) key_yank_from_cutbuffer);
	key_unbind("transpose_characters", (SIGNAL_FUNC) key_transpose_characters);
	key_unbind("transpose_words", (SIGNAL_FUNC) key_transpose_words);

	key_unbind("capitalize_word", (SIGNAL_FUNC) key_capitalize_word);
	key_unbind("downcase_word", (SIGNAL_FUNC) key_downcase_word);
	key_unbind("upcase_word", (SIGNAL_FUNC) key_upcase_word);

	key_unbind("send_line", (SIGNAL_FUNC) key_send_line);
	key_unbind("word_completion_backward", (SIGNAL_FUNC) key_word_completion_backward);
	key_unbind("word_completion", (SIGNAL_FUNC) key_word_completion);
	key_unbind("erase_completion", (SIGNAL_FUNC) key_erase_completion);
	key_unbind("check_replaces", (SIGNAL_FUNC) key_check_replaces);

	key_unbind("previous_window", (SIGNAL_FUNC) key_previous_window);
	key_unbind("next_window", (SIGNAL_FUNC) key_next_window);
	key_unbind("upper_window", (SIGNAL_FUNC) key_upper_window);
	key_unbind("lower_window", (SIGNAL_FUNC) key_lower_window);
	key_unbind("left_window", (SIGNAL_FUNC) key_left_window);
	key_unbind("right_window", (SIGNAL_FUNC) key_right_window);
	key_unbind("active_window", (SIGNAL_FUNC) key_active_window);
	key_unbind("next_window_item", (SIGNAL_FUNC) key_next_window_item);
	key_unbind("previous_window_item", (SIGNAL_FUNC) key_previous_window_item);

	key_unbind("refresh_screen", (SIGNAL_FUNC) irssi_redraw);
	key_unbind("scroll_backward", (SIGNAL_FUNC) key_scroll_backward);
	key_unbind("scroll_forward", (SIGNAL_FUNC) key_scroll_forward);
	key_unbind("scroll_start", (SIGNAL_FUNC) key_scroll_start);
	key_unbind("scroll_end", (SIGNAL_FUNC) key_scroll_end);

	key_unbind("escape_char", (SIGNAL_FUNC) key_escape);
	key_unbind("insert_text", (SIGNAL_FUNC) key_insert_text);
	key_unbind("change_window", (SIGNAL_FUNC) key_change_window);
	key_unbind("stop_irc", (SIGNAL_FUNC) key_sig_stop);
	keyboard_destroy(keyboard);
        g_array_free(paste_buffer, TRUE);
        g_array_free(paste_buffer_rest, TRUE);

        key_configure_thaw();

	signal_remove("window changed automatic", (SIGNAL_FUNC) sig_window_auto_changed);
	signal_remove("gui entry redirect", (SIGNAL_FUNC) sig_gui_entry_redirect);
	signal_remove("gui key pressed", (SIGNAL_FUNC) sig_gui_key_pressed);
	signal_remove("setup changed", (SIGNAL_FUNC) setup_changed);
}
