/*
 fe-common-core.c : irssi

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
#include "levels.h"
#include "settings.h"
#include "channels.h"

#include "fe-queries.h"
#include "hilight-text.h"
#include "command-history.h"
#include "completion.h"
#include "keyboard.h"
#include "printtext.h"
#include "formats.h"
#include "themes.h"
#include "translation.h"
#include "fe-windows.h"
#include "window-items.h"
#include "window-save.h"

#include <signal.h>

void autorun_init(void);
void autorun_deinit(void);

void fe_channels_init(void);
void fe_channels_deinit(void);

void fe_core_log_init(void);
void fe_core_log_deinit(void);

void fe_exec_init(void);
void fe_exec_deinit(void);

void fe_expandos_init(void);
void fe_expandos_deinit(void);

void fe_ignore_init(void);
void fe_ignore_deinit(void);

void fe_ignore_messages_init(void);
void fe_ignore_messages_deinit(void);

void fe_log_init(void);
void fe_log_deinit(void);

void fe_messages_init(void);
void fe_messages_deinit(void);

void fe_modules_init(void);
void fe_modules_deinit(void);

void fe_server_init(void);
void fe_server_deinit(void);

void fe_settings_init(void);
void fe_settings_deinit(void);

void window_activity_init(void);
void window_activity_deinit(void);

void window_commands_init(void);
void window_commands_deinit(void);

void fe_core_commands_init(void);
void fe_core_commands_deinit(void);

static void sig_connected(SERVER_REC *server)
{
	MODULE_DATA_SET(server, g_new0(MODULE_SERVER_REC, 1));
}

static void sig_disconnected(SERVER_REC *server)
{
	g_free(MODULE_DATA(server));
}

static void sig_channel_created(CHANNEL_REC *channel)
{
	MODULE_DATA_SET(channel, g_new0(MODULE_CHANNEL_REC, 1));
}

static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	g_free(MODULE_DATA(channel));
}

void fe_common_core_init(void)
{
	settings_add_bool("lookandfeel", "timestamps", TRUE);
	settings_add_bool("lookandfeel", "msgs_timestamps", FALSE);
	settings_add_bool("lookandfeel", "hide_text_style", FALSE);
	settings_add_bool("lookandfeel", "bell_beeps", FALSE);
	settings_add_str("lookandfeel", "beep_on_msg", "");
	settings_add_bool("lookandfeel", "beep_when_away", TRUE);

	settings_add_bool("lookandfeel", "use_status_window", TRUE);
	settings_add_bool("lookandfeel", "use_msgs_window", FALSE);

	themes_init();
        theme_register(fecommon_core_formats);

	autorun_init();
	command_history_init();
	completion_init();
	hilight_text_init();
	keyboard_init();
	printtext_init();
	formats_init();
#ifndef WIN32
        fe_exec_init();
#endif
        fe_expandos_init();
	fe_ignore_init();
	fe_log_init();
	fe_modules_init();
	fe_server_init();
	fe_settings_init();
	translation_init();
	windows_init();
	window_activity_init();
	window_commands_init();
	window_items_init();
	window_save_init();
	fe_core_commands_init();

        fe_channels_init();
        fe_queries_init();

	fe_messages_init();
	fe_ignore_messages_init();

	settings_check();

        signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
        signal_add_last("server disconnected", (SIGNAL_FUNC) sig_disconnected);
        signal_add_first("channel created", (SIGNAL_FUNC) sig_channel_created);
        signal_add_last("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}

void fe_common_core_deinit(void)
{
	autorun_deinit();
	hilight_text_deinit();
	command_history_deinit();
	completion_deinit();
	keyboard_deinit();
	printtext_deinit();
	formats_deinit();
#ifndef WIN32
        fe_exec_deinit();
#endif
        fe_expandos_deinit();
	fe_ignore_deinit();
	fe_log_deinit();
	fe_modules_deinit();
	fe_server_deinit();
	fe_settings_deinit();
	translation_deinit();
	windows_deinit();
	window_activity_deinit();
	window_commands_deinit();
	window_items_deinit();
	window_save_deinit();
	fe_core_commands_deinit();

        fe_channels_deinit();
        fe_queries_deinit();

	fe_messages_deinit();
	fe_ignore_messages_init();

        theme_unregister();
	themes_deinit();

        signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
        signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
        signal_remove("channel created", (SIGNAL_FUNC) sig_channel_created);
        signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}

void glog_func(const char *log_domain, GLogLevelFlags log_level,
	       const char *message)
{
	const char *reason;

	switch (log_level) {
	case G_LOG_LEVEL_WARNING:
                reason = "warning";
                break;
	case G_LOG_LEVEL_CRITICAL:
                reason = "critical";
		break;
	default:
		reason = "error";
                break;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
		    TXT_GLIB_ERROR, reason, message);
}

void fe_common_core_finish_init(void)
{
	WINDOW_REC *window;

	g_log_set_handler(G_LOG_DOMAIN,
			  (GLogLevelFlags) (G_LOG_LEVEL_CRITICAL |
					    G_LOG_LEVEL_WARNING),
			  (GLogFunc) glog_func, NULL);

	signal_emit("irssi init read settings", 0);

#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	windows_restore();
	if (windows != NULL)
		return;

	if (settings_get_bool("use_status_window")) {
		window = window_create(NULL, TRUE);
		window_set_name(window, "(status)");
		window_set_level(window, MSGLEVEL_ALL ^
				 (settings_get_bool("use_msgs_window") ?
				  (MSGLEVEL_MSGS|MSGLEVEL_DCCMSGS) : 0));
	}

	if (settings_get_bool("use_msgs_window")) {
		window = window_create(NULL, TRUE);
		window_set_name(window, "(msgs)");
		window_set_level(window, MSGLEVEL_MSGS|MSGLEVEL_DCCMSGS);
	}

	if (windows == NULL) {
		/* we have to have at least one window.. */
                window = window_create(NULL, TRUE);
	}
}
