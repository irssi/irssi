/*
 term-dummy.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include "signals.h"

#include "fe-windows.h"

static int newline;

static GIOChannel *stdin_channel;
static int readtag;
static GString *input;

static void sig_gui_printtext(WINDOW_REC *window, void *fgcolor,
                              void *bgcolor, void *pflags,
                              char *str, void *level)
{
	if (newline) {
		newline = FALSE;
		printf("\r");
	}

	printf("%s", str);
}

static void sig_gui_printtext_finished(WINDOW_REC *window)
{
	printf("\n");
	newline = TRUE;
}

static void sig_window_created(WINDOW_REC *window)
{
	window->width = 80;
	window->height = 25;
}

static void readline(void)
{
        unsigned char buffer[128];
	char *p;
	int ret, i;

	ret = read(0, buffer, sizeof(buffer));
	if (ret == 0 || (ret == -1 && errno != EINTR)) {
		/* lost terminal */
		signal_emit("command quit", 1, "Lost terminal");
                return;
	}

	for (i = 0; i < ret; i++)
		g_string_append_c(input, buffer[i]);

	p = strchr(input->str, '\n');
	if (p != NULL) {
		*p = '\0';
		signal_emit("send command", 3, input->str,
			    active_win->active_server, active_win->active);
		*p = '\n';
		g_string_erase(input, 0, (int) (p-input->str)+1);
	}
}

void term_dummy_init(void)
{
	newline = TRUE;
	input = g_string_new(NULL);

	signal_add("gui print text", (SIGNAL_FUNC) sig_gui_printtext);
	signal_add("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_add("window created", (SIGNAL_FUNC) sig_window_created);

        stdin_channel = g_io_channel_unix_new(0);
	readtag = g_input_add_full(stdin_channel,
				   G_PRIORITY_HIGH, G_INPUT_READ,
				   (GInputFunction) readline, NULL);
        g_io_channel_unref(stdin_channel);
}

void term_dummy_deinit(void)
{
	signal_remove("gui print text", (SIGNAL_FUNC) sig_gui_printtext);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_remove("window created", (SIGNAL_FUNC) sig_window_created);

	g_source_remove(readtag);
	g_string_free(input, TRUE);
}
