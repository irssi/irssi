/*
 core.c : irssi

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
#include <signal.h>

#include "args.h"
#include "pidwait.h"
#include "misc.h"

#include "net-disconnect.h"
#include "net-sendbuffer.h"
#include "signals.h"
#include "settings.h"
#include "session.h"

#include "chat-protocols.h"
#include "servers.h"
#include "chatnets.h"
#include "commands.h"
#include "expandos.h"
#include "write-buffer.h"
#include "log.h"
#include "rawlog.h"
#include "ignore.h"

#include "channels.h"
#include "queries.h"
#include "nicklist.h"
#include "nickmatch-cache.h"

#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
   struct rlimit orig_core_rlimit;
#endif

void chat_commands_init(void);
void chat_commands_deinit(void);

void log_away_init(void);
void log_away_deinit(void);

int irssi_gui;
int irssi_init_finished;

static char *irssi_dir, *irssi_config_file;
static GSList *dialog_type_queue, *dialog_text_queue;

const char *get_irssi_dir(void)
{
        return irssi_dir;
}

/* return full path for ~/.irssi/config */
const char *get_irssi_config(void)
{
        return irssi_config_file;
}

static void read_settings(void)
{
#ifndef WIN32
	static int signals[] = {
		SIGHUP, SIGINT, SIGQUIT, SIGTERM,
		SIGALRM, SIGUSR1, SIGUSR2
	};
	static char *signames[] = {
		"hup", "int", "quit", "term",
		"alrm", "usr1", "usr2"
	};

	const char *ignores;
	struct sigaction act;
        int n;

	ignores = settings_get_str("ignore_signals");

	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		act.sa_handler = find_substr(ignores, signames[n]) ?
			SIG_IGN : SIG_DFL;
		sigaction(signals[n], &act, NULL);
	}

#ifdef HAVE_SYS_RESOURCE_H
	if (!settings_get_bool("override_coredump_limit"))
		setrlimit(RLIMIT_CORE, &orig_core_rlimit);
	else {
		struct rlimit rlimit;

                rlimit.rlim_cur = RLIM_INFINITY;
                rlimit.rlim_max = RLIM_INFINITY;
		if (setrlimit(RLIMIT_CORE, &rlimit) == -1)
                        settings_set_bool("override_coredump_limit", FALSE);
	}
#endif
#endif
}

static void sig_gui_dialog(const char *type, const char *text)
{
	dialog_type_queue = g_slist_append(dialog_type_queue, g_strdup(type));
	dialog_text_queue = g_slist_append(dialog_text_queue, g_strdup(text));
}

static void sig_init_finished(void)
{
	GSList *type, *text;

        signal_remove("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);

	/* send the dialog texts that were in queue before irssi
	   was initialized */
	type = dialog_type_queue;
        text = dialog_text_queue;
	for (; text != NULL; text = text->next, type = type->next) {
		signal_emit("gui dialog", 2, type->data, text->data);
		g_free(type->data);
                g_free(text->data);
	}
        g_slist_free(dialog_type_queue);
        g_slist_free(dialog_text_queue);
}

void core_init_paths(int argc, char *argv[])
{
	static struct poptOption options[] = {
		{ "config", 0, POPT_ARG_STRING, NULL, 0, "Configuration file location (~/.irssi/config)", "PATH" },
		{ "home", 0, POPT_ARG_STRING, NULL, 0, "Irssi home dir location (~/.irssi)", "PATH" },
		{ NULL, '\0', 0, NULL }
	};
	char *str;
	int n, len;

	for (n = 1; n < argc; n++) {
		if (strncmp(argv[n], "--home=", 7) == 0) {
                        g_free_not_null(irssi_dir);
                        irssi_dir = convert_home(argv[n]+7);
                        len = strlen(irssi_dir);
			if (irssi_dir[len-1] == G_DIR_SEPARATOR)
				irssi_dir[len-1] = '\0';
		} else if (strncmp(argv[n], "--config=", 9) == 0) {
                        g_free_not_null(irssi_config_file);
			irssi_config_file = convert_home(argv[n]+9);
		}
	}

	if (irssi_dir != NULL && !g_path_is_absolute(irssi_dir)) {
		str = irssi_dir;
		irssi_dir = g_strdup_printf("%s/%s", g_get_current_dir(), str);
		g_free(str);
	}

	if (irssi_config_file != NULL &&
	    !g_path_is_absolute(irssi_config_file)) {
		str = irssi_config_file;
		irssi_config_file =
			g_strdup_printf("%s/%s", g_get_current_dir(), str);
		g_free(str);
	}

	args_register(options);

        if (irssi_dir == NULL)
		irssi_dir = g_strdup_printf(IRSSI_DIR_FULL, g_get_home_dir());
	if (irssi_config_file == NULL)
		irssi_config_file = g_strdup_printf("%s/"IRSSI_HOME_CONFIG, irssi_dir);

	session_set_binary(argv[0]);
}

static void sig_irssi_init_finished(void)
{
        irssi_init_finished = TRUE;
}

void core_init(int argc, char *argv[])
{
	dialog_type_queue = NULL;
	dialog_text_queue = NULL;

	modules_init();
#ifndef WIN32
	pidwait_init();
#endif

	net_disconnect_init();
	net_sendbuffer_init();
	signals_init();

	signal_add_first("gui dialog", (SIGNAL_FUNC) sig_gui_dialog);
	signal_add_first("irssi init finished", (SIGNAL_FUNC) sig_init_finished);

	settings_init();
	commands_init();
	nickmatch_cache_init();
        session_init();

	chat_protocols_init();
	chatnets_init();
        expandos_init();
	ignore_init();
	servers_init();
        write_buffer_init();
	log_init();
	log_away_init();
	rawlog_init();

	channels_init();
	queries_init();
	nicklist_init();

	chat_commands_init();

	settings_add_str("misc", "ignore_signals", "");
	settings_add_bool("misc", "override_coredump_limit", TRUE);

#ifdef HAVE_SYS_RESOURCE_H
	getrlimit(RLIMIT_CORE, &orig_core_rlimit);
#endif
	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);

	settings_check();

        module_register("core", "core");
}

void core_deinit(void)
{
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);

	chat_commands_deinit();

	nicklist_deinit();
	queries_deinit();
	channels_deinit();

	rawlog_deinit();
	log_away_deinit();
	log_deinit();
        write_buffer_deinit();
	servers_deinit();
	ignore_deinit();
        expandos_deinit();
	chatnets_deinit();
	chat_protocols_deinit();

        session_deinit();
        nickmatch_cache_deinit();
	commands_deinit();
	settings_deinit();
	signals_deinit();
	net_sendbuffer_deinit();
	net_disconnect_deinit();

#ifndef WIN32
	pidwait_deinit();
#endif
	modules_deinit();

	g_free(irssi_dir);
        g_free(irssi_config_file);
}
