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

#include <irssi/src/core/args.h>
#include <irssi/src/core/pidwait.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/core/net-disconnect.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/session.h>
#ifdef HAVE_CAPSICUM
#include <irssi/src/core/capsicum.h>
#endif

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/expandos.h>
#include <irssi/src/core/ignore.h>
#include <irssi/src/core/log.h>
#include <irssi/src/core/rawlog.h>
#include <irssi/src/core/recode.h>
#include <irssi/src/core/refstrings.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/write-buffer.h>
#include <irssi/src/core/utf8.h>

#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/nicklist.h>
#include <irssi/src/core/nickmatch-cache.h>

#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
   static struct rlimit orig_core_rlimit;
#endif

void chat_commands_init(void);
void chat_commands_deinit(void);

void log_away_init(void);
void log_away_deinit(void);

void wcwidth_wrapper_init(void);
void wcwidth_wrapper_deinit(void);

int irssi_gui;
int irssi_init_finished;
int sighup_received;
int sigterm_received;
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

static void sig_hup(int signo)
{
	sighup_received = TRUE;
}

static void sig_term(int signo)
{
	sigterm_received = TRUE;
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

	act.sa_handler = sig_hup;
	sigaction(SIGHUP, &act, NULL);

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		if (find_substr(ignores, signames[n])) {
			act.sa_handler = SIG_IGN;
		} else {
			/* set default handlers */
			if (signals[n] == SIGTERM)
				act.sa_handler = sig_term;
			else
				act.sa_handler = SIG_DFL;
		}
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

static void reread_setup(void)
{
	signal_emit("setup reread chatnets", 0);
	signal_emit("setup reread servers", 0);
	signal_emit("setup reread channels", 0);
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
#ifdef HAVE_CAPSICUM
	capsicum_init();
#endif

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
	i_refstr_init();
	special_vars_init();
	wcwidth_wrapper_init();
	utf8_init();

	settings_add_str("misc", "ignore_signals", "");
	settings_add_bool("misc", "override_coredump_limit", FALSE);
	settings_add_bool("misc", "quit_on_hup", FALSE);
	settings_add_str("misc", "autoload_modules", "irc dcc flood notifylist perl otr");

#ifdef HAVE_SYS_RESOURCE_H
	getrlimit(RLIMIT_CORE, &orig_core_rlimit);
#endif
	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("setup reread", (SIGNAL_FUNC) reread_setup);
	signal_add("irssi init read settings", (SIGNAL_FUNC) reread_setup);
	signal_add_last("chat protocol created", (SIGNAL_FUNC) reread_setup);
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);

	settings_check();

        module_register("core", "core");
}

void core_deinit(void)
{
	module_uniq_destroy("WINDOW ITEM TYPE");

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("setup reread", (SIGNAL_FUNC) reread_setup);
	signal_remove("irssi init read settings", (SIGNAL_FUNC) reread_setup);
	signal_remove("chat protocol created", (SIGNAL_FUNC) reread_setup);
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);

	utf8_deinit();
	wcwidth_wrapper_deinit();
	special_vars_deinit();
	i_refstr_deinit();
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

#ifdef HAVE_CAPSICUM
	capsicum_deinit();
#endif
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
