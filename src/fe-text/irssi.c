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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/core/modules-load.h>
#include <irssi/src/core/args.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/core.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/session.h>
#include <irssi/src/core/servers.h>

#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/fe-common-core.h>
#include <irssi/src/fe-common/core/fe-settings.h>
#include <irssi/src/fe-common/core/themes.h>

#include <irssi/src/fe-text/term.h>
#include <irssi/src/fe-text/gui-entry.h>
#include <irssi/src/fe-text/mainwindows.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/fe-text/gui-readline.h>
#include <irssi/src/fe-text/statusbar.h>
#include <irssi/src/fe-text/gui-windows.h>
#include <irssi/irssi-version.h>
#include <irssi/src/fe-text/sidepanels.h>

#include <signal.h>
#include <locale.h>

void gui_expandos_init(void);
void gui_expandos_deinit(void);

void textbuffer_commands_init(void);
void textbuffer_commands_deinit(void);

void textbuffer_formats_init(void);
void textbuffer_formats_deinit(void);

void lastlog_init(void);
void lastlog_deinit(void);

void mainwindow_activity_init(void);
void mainwindow_activity_deinit(void);

void mainwindows_layout_init(void);
void mainwindows_layout_deinit(void);

void sidepanels_init(void);
void sidepanels_deinit(void);

static int dirty, full_redraw;

static GMainLoop *main_loop;
int quitting;

static int display_firsttimer = FALSE;
static unsigned int user_settings_changed = 0;

static void sig_exit(void)
{
	quitting = TRUE;
}

static void sig_settings_userinfo_changed(gpointer changedp)
{
	user_settings_changed = GPOINTER_TO_UINT(changedp);
}

static void sig_autoload_modules(void)
{
	char **list, **module;
	list = g_strsplit_set(settings_get_str("autoload_modules"), " ,", -1);
	for (module = list; *module != NULL; module++) {
		char *tmp;
		if ((tmp = strchr(*module, ':')) != NULL)
			*tmp = ' ';
		tmp = g_strdup_printf("-silent %s", *module);
		signal_emit("command load", 1, tmp);
		g_free(tmp);
	}
	g_strfreev(list);
}

/* redraw irssi's screen.. */
void irssi_redraw(void)
{
	dirty = TRUE;
	full_redraw = TRUE;
}

void irssi_set_dirty(void)
{
	dirty = TRUE;
}

static void dirty_check(void)
{
	if (!dirty)
		return;

	term_resize_dirty();

	if (full_redraw) {
		full_redraw = FALSE;

		/* first clear the screen so curses will be
		   forced to redraw the screen */
		term_clear();
		term_refresh(NULL);

		mainwindows_redraw();
		statusbar_redraw(NULL, TRUE);
	}

	mainwindows_redraw_dirty();
	statusbar_redraw_dirty();
	term_refresh(NULL);

	dirty = FALSE;
}

static void textui_init(void)
{
#ifdef SIGTRAP
	struct sigaction act;

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;
	sigaction(SIGTRAP, &act, NULL);
#endif

	irssi_gui = IRSSI_GUI_TEXT;
	core_init();
	fe_common_core_init();

	theme_register(gui_text_formats);
	signal_add("settings userinfo changed", (SIGNAL_FUNC) sig_settings_userinfo_changed);
	signal_add("module autoload", (SIGNAL_FUNC) sig_autoload_modules);
	signal_add_last("gui exit", (SIGNAL_FUNC) sig_exit);
}

static int critical_fatal_section_begin(void)
{
	return g_log_set_always_fatal(G_LOG_FATAL_MASK | G_LOG_LEVEL_CRITICAL);
}

static void critical_fatal_section_end(int loglev)
{
	g_log_set_always_fatal(loglev);
}

static void textui_finish_init(void)
{
	int loglev;
	quitting = FALSE;

	term_refresh_freeze();
	textbuffer_init();
	textbuffer_view_init();
	textbuffer_commands_init();
	textbuffer_formats_init();
	gui_expandos_init();
	gui_printtext_init();
	gui_readline_init();
	gui_entry_init();
	lastlog_init();
	mainwindows_init();
	mainwindow_activity_init();
	mainwindows_layout_init();
	gui_windows_init();
	sidepanels_init();
	/* Temporarily raise the fatal level to abort on config errors. */
	loglev = critical_fatal_section_begin();
	statusbar_init();
	critical_fatal_section_end(loglev);

	settings_check();

	module_register("core", "fe-text");

	dirty_check();

	/* Temporarily raise the fatal level to abort on config errors. */
	loglev = critical_fatal_section_begin();
	fe_common_core_finish_init();
	critical_fatal_section_end(loglev);
	term_refresh_thaw();

	signal_emit("irssi init finished", 0);
	statusbar_redraw(NULL, TRUE);

	if (servers == NULL && lookup_servers == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CRAP | MSGLEVEL_NO_ACT, TXT_IRSSI_BANNER);
	}

	if (display_firsttimer) {
		printformat(NULL, NULL, MSGLEVEL_CRAP | MSGLEVEL_NO_ACT, TXT_WELCOME_FIRSTTIME);
	}

	/* see irc-servers-setup.c:init_userinfo */
	if (user_settings_changed)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_WELCOME_INIT_SETTINGS);
	if (user_settings_changed & USER_SETTINGS_REAL_NAME)
		fe_settings_set_print("real_name");
	if (user_settings_changed & USER_SETTINGS_USER_NAME)
		fe_settings_set_print("user_name");
	if (user_settings_changed & USER_SETTINGS_NICK)
		fe_settings_set_print("nick");
	if (user_settings_changed & USER_SETTINGS_HOSTNAME)
		fe_settings_set_print("hostname");

	term_environment_check();
}

static void textui_deinit(void)
{
	signal(SIGINT, SIG_DFL);

	term_refresh_freeze();
	while (modules != NULL)
		module_unload(modules->data);

	dirty_check(); /* one last time to print any quit messages */
	signal_remove("settings userinfo changed", (SIGNAL_FUNC) sig_settings_userinfo_changed);
	signal_remove("module autoload", (SIGNAL_FUNC) sig_autoload_modules);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_exit);

	lastlog_deinit();
	statusbar_deinit();
	sidepanels_deinit();
	gui_entry_deinit();
	gui_printtext_deinit();
	gui_readline_deinit();
	gui_windows_deinit();
	mainwindows_layout_deinit();
	mainwindow_activity_deinit();
	mainwindows_deinit();
	gui_expandos_deinit();
	textbuffer_formats_deinit();
	textbuffer_commands_deinit();
	textbuffer_view_deinit();
	textbuffer_deinit();

	term_refresh_thaw();
	term_deinit();

	theme_unregister();

	fe_common_core_deinit();
	core_deinit();
}

static void check_files(void)
{
	struct stat statbuf;

	if (stat(get_irssi_dir(), &statbuf) != 0) {
		/* ~/.irssi doesn't exist, first time running irssi */
		display_firsttimer = TRUE;
	}
}

int main(int argc, char **argv)
{
	static int version = 0;
	static GOptionEntry options[] = { { "version", 'v', 0, G_OPTION_ARG_NONE, &version,
		                            "Display Irssi version", NULL },
		                          { NULL } };
	int loglev;

	core_register_options();
	fe_common_core_register_options();
	args_register(options);
	args_execute(argc, argv);

	if (version) {
		printf(PACKAGE_TARNAME " " PACKAGE_VERSION " (%d %04d)\n", IRSSI_VERSION_DATE,
		       IRSSI_VERSION_TIME);
		return 0;
	}

	srand(time(NULL));

	quitting = FALSE;
	core_preinit(argv[0]);

	check_files();

	/* setlocale() must be called at the beginning before any calls that
	   affect it, especially regexps seem to break if they're generated
	   before this call.

	   locales aren't actually used for anything else than autodetection
	   of UTF-8 currently..

	   furthermore to get the users's charset with g_get_charset() properly
	   you have to call setlocale(LC_ALL, "") */
	setlocale(LC_ALL, "");

	/* Temporarily raise the fatal level to abort on config errors. */
	loglev = critical_fatal_section_begin();
	textui_init();

	if (!term_init()) {
		fprintf(stderr, "Can't initialize screen handling.\n");
		return 1;
	}

	critical_fatal_section_end(loglev);

	textui_finish_init();
	main_loop = g_main_loop_new(NULL, TRUE);

	/* Does the same as g_main_run(main_loop), except we
	   can call our dirty-checker after each iteration */
	while (!quitting) {
		if (sigterm_received) {
			sigterm_received = FALSE;
			signal_emit("gui exit", 0);
		}

		if (sighup_received) {
			sighup_received = FALSE;

			if (settings_get_bool("quit_on_hup")) {
				signal_emit("gui exit", 0);
			} else {
				signal_emit("command reload", 1, "");
			}
		}

		dirty_check();

		term_refresh_freeze();
		g_main_context_iteration(NULL, TRUE);
		term_refresh_thaw();
	}

	g_main_loop_unref(main_loop);
	textui_deinit();

	session_upgrade(); /* if we /UPGRADEd, start the new process */
	return 0;
}
