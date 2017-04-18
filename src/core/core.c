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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <signal.h>

#include "args.h"
#include "pidwait.h"
#include "misc.h"

#include "net-disconnect.h"
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
#include "recode.h"

#include "channels.h"
#include "queries.h"
#include "nicklist.h"
#include "nickmatch-cache.h"

void chat_commands_init(void);
void chat_commands_deinit(void);

void log_away_init(void);
void log_away_deinit(void);

int irssi_gui;
int irssi_init_finished;
int reload_config;
time_t client_start_time;

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

static void sig_reload_config(int signo)
{
        reload_config = TRUE;
}

static void read_settings(void)
{
	static int signals[] = {
		SIGINT, SIGQUIT, SIGTERM,
		SIGALRM, SIGUSR1, SIGUSR2
	};
	static char *signames[] = {
		"int", "quit", "term",
		"alrm", "usr1", "usr2"
	};

	const char *ignores;
	struct sigaction act;
        int n;

	ignores = settings_get_str("ignore_signals");

	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	/* reload config on SIGHUP */
        act.sa_handler = sig_reload_config;
	sigaction(SIGHUP, &act, NULL);

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		act.sa_handler = find_substr(ignores, signames[n]) ?
			SIG_IGN : SIG_DFL;
		sigaction(signals[n], &act, NULL);
	}
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

static char *fix_path(const char *str)
{
	char *new_str = convert_home(str);

	if (!g_path_is_absolute(new_str)) {
		char *tmp_str = new_str;
		char *current_dir = g_get_current_dir();

		new_str = g_build_path(G_DIR_SEPARATOR_S, current_dir, tmp_str, NULL);

		g_free(current_dir);
		g_free(tmp_str);
	}

	return new_str;
}

void core_register_options(void)
{
	static GOptionEntry options[] = {
		{ "config", 0, 0, G_OPTION_ARG_STRING, &irssi_config_file, "Configuration file location (~/.irssi/config)", "PATH" },
		{ "home", 0, 0, G_OPTION_ARG_STRING, &irssi_dir, "Irssi home dir location (~/.irssi)", "PATH" },
		{ NULL }
	};

	args_register(options);
	session_register_options();
}

void core_preinit(const char *path)
{
	const char *home;
	char *str;
	int len;

	if (irssi_dir == NULL) {
		home = g_get_home_dir();
		if (home == NULL)
			home = ".";

		irssi_dir = g_strdup_printf(IRSSI_DIR_FULL, home);
	} else {
		str = irssi_dir;
		irssi_dir = fix_path(str);
		g_free(str);
		len = strlen(irssi_dir);
		if (irssi_dir[len-1] == G_DIR_SEPARATOR)
			irssi_dir[len-1] = '\0';
	}
	if (irssi_config_file == NULL)
		irssi_config_file = g_strdup_printf("%s/"IRSSI_HOME_CONFIG, irssi_dir);
	else {
		str = irssi_config_file;
		irssi_config_file = fix_path(str);
		g_free(str);
	}

	session_set_binary(path);
}

static void sig_irssi_init_finished(void)
{
        irssi_init_finished = TRUE;
}

void core_init(void)
{
	dialog_type_queue = NULL;
	dialog_text_queue = NULL;
	client_start_time = time(NULL);

	modules_init();
	pidwait_init();

	net_disconnect_init();
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
	recode_init();

	channels_init();
	queries_init();
	nicklist_init();

	chat_commands_init();

	settings_add_str("misc", "ignore_signals", "");

	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);

	settings_check();

        module_register("core", "core");
}

void core_deinit(void)
{
	module_uniq_destroy("WINDOW ITEM TYPE");

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);

	chat_commands_deinit();

	nicklist_deinit();
	queries_deinit();
	channels_deinit();

	recode_deinit();
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
	net_disconnect_deinit();

	pidwait_deinit();
	modules_deinit();

	g_free(irssi_dir);
        g_free(irssi_config_file);
}
