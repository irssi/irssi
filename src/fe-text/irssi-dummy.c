/*
 irssi-dummy.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "module-formats.h"
#include "modules-load.h"
#include "args.h"
#include "signals.h"
#include "levels.h"
#include "core.h"
#include "settings.h"
#include "session.h"

#include "printtext.h"
#include "fe-common-core.h"
#include "fe-windows.h"

#include <signal.h>

#ifdef HAVE_STATIC_PERL
void perl_core_init(void);
void perl_core_deinit(void);

void fe_perl_init(void);
void fe_perl_deinit(void);
#endif

void irc_init(void);
void irc_deinit(void);

void fe_common_irc_init(void);
void fe_common_irc_deinit(void);

static GMainLoop *main_loop;
static int newline;

static GIOChannel *stdin_channel;
static int readtag;
static GString *input;

static void sig_exit(void)
{
	g_main_quit(main_loop);
}

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

static void dummyui_init(void)
{
	irssi_gui = IRSSI_GUI_TEXT;

	core_init();
	irc_init();
	fe_common_core_init();
	fe_common_irc_init();
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

static void dummyui_finish_init(void)
{
	settings_check();
	module_register("core", "fe-text");

#ifdef HAVE_STATIC_PERL
	perl_core_init();
	fe_perl_init();
#endif

	newline = TRUE;

	signal_add("gui print text", (SIGNAL_FUNC) sig_gui_printtext);
	signal_add("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_add("window created", (SIGNAL_FUNC) sig_window_created);
	signal_add_last("gui exit", (SIGNAL_FUNC) sig_exit);

	input = g_string_new(NULL);
        stdin_channel = g_io_channel_unix_new(0);
	readtag = g_input_add_full(stdin_channel,
				   G_PRIORITY_HIGH, G_INPUT_READ,
				   (GInputFunction) readline, NULL);
        g_io_channel_unref(stdin_channel);

	fe_common_core_finish_init();
	signal_emit("irssi init finished", 0);
}

static void dummyui_deinit(void)
{
	signal(SIGINT, SIG_DFL);

	while (modules != NULL)
		module_unload(modules->data);

#ifdef HAVE_STATIC_PERL
        perl_core_deinit();
        fe_perl_deinit();
#endif

	signal_remove("gui print text", (SIGNAL_FUNC) sig_gui_printtext);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_gui_printtext_finished);
	signal_remove("window created", (SIGNAL_FUNC) sig_window_created);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_exit);

	g_source_remove(readtag);
	g_string_free(input, TRUE);

	fe_common_irc_deinit();
	fe_common_core_deinit();
	irc_deinit();
	core_deinit();
}

#ifdef WIN32
static void winsock_init(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("Error initializing winsock\n");
		exit(1);
	}
}
#endif

int main(int argc, char **argv)
{
	core_init_paths(argc, argv);

#ifdef WIN32
        winsock_init();
#endif
#ifdef HAVE_SOCKS
	SOCKSinit(argv[0]);
#endif

	dummyui_init();
	args_execute(argc, argv);

	dummyui_finish_init();

	main_loop = g_main_new(TRUE);
	g_main_run(main_loop);
	g_main_destroy(main_loop);

	dummyui_deinit();

        session_upgrade(); /* if we /UPGRADEd, start the new process */
	return 0;
}
