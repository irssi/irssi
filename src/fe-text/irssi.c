/*
 irssi.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "args.h"
#include "signals.h"
#include "core.h"

#include "fe-common-core.h"
#include "fe-common-irc.h"
#include "themes.h"

#include "screen.h"
#include "gui-entry.h"
#include "mainwindows.h"
#include "gui-printtext.h"
#include "gui-readline.h"
#include "gui-special-vars.h"
#include "statusbar.h"
#include "gui-textwidget.h"
#include "gui-windows.h"

#include <signal.h>

#ifdef HAVE_STATIC_PERL
void perl_init(void);
void perl_deinit(void);
#endif

void irc_init(void);
void irc_deinit(void);

void mainwindow_activity_init(void);
void mainwindow_activity_deinit(void);

static GMainLoop *main_loop;
int quitting;

static void sig_exit(void)
{
	g_main_quit(main_loop);
}

/* redraw irssi's screen.. */
void irssi_redraw(void)
{
	clear();
	refresh();

	/* windows */
        mainwindows_redraw();
	/* statusbar */
	statusbar_redraw(NULL);
	/* entry line */
	gui_entry_redraw();
}

static void textui_init(void)
{
	static struct poptOption options[] = {
		POPT_AUTOHELP
		{ NULL, '\0', 0, NULL }
	};

	args_register(options);

	irssi_gui = IRSSI_GUI_TEXT;
	core_init();
	irc_init();
	fe_common_core_init();
	fe_common_irc_init();

	theme_register(gui_text_formats);
	signal_add("gui exit", (SIGNAL_FUNC) sig_exit);
}

static void textui_finish_init(void)
{
	quitting = FALSE;

	screen_refresh_freeze();
	gui_entry_init();
	gui_printtext_init();
	gui_readline_init();
	gui_special_vars_init();
	gui_textwidget_init();
	mainwindows_init();
	mainwindow_activity_init();
	gui_windows_init();
	statusbar_init();

	fe_common_core_finish_init();
	fe_common_irc_finish_init();

#ifdef HAVE_STATIC_PERL
        perl_init();
#endif
	signal_emit("irssi init finished", 0);

	screen_refresh_thaw();
}

static void textui_deinit(void)
{
	quitting = TRUE;
	signal(SIGINT, SIG_DFL);

	while (modules != NULL)
		module_unload(modules->data);

	signal_remove("gui exit", (SIGNAL_FUNC) sig_exit);
	gui_textwidget_deinit();
	gui_special_vars_deinit();
	statusbar_deinit();
	gui_printtext_deinit();
	gui_readline_deinit();
	gui_windows_deinit();
	mainwindow_activity_deinit();
	mainwindows_deinit();
	gui_entry_deinit();
	deinit_screen();

#ifdef HAVE_STATIC_PERL
        perl_deinit();
#endif

	theme_unregister();

	fe_common_irc_deinit();
	fe_common_core_deinit();
	irc_deinit();
	core_deinit();
}

int main(int argc, char **argv)
{
#ifdef HAVE_SOCKS
	SOCKSinit(argv[0]);
#endif
#ifdef ENABLE_NLS
	/* initialize the i18n stuff */
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
#endif

	textui_init();
	args_execute(argc, argv);

	if (!init_screen())
		g_error(_("Can't initialize screen handling, quitting.\n"));

	textui_finish_init();
	main_loop = g_main_new(TRUE);
	g_main_run(main_loop);
	g_main_destroy(main_loop);
	textui_deinit();

#ifdef MEM_DEBUG
	ig_mem_profile();
#endif

	return 0;
}
