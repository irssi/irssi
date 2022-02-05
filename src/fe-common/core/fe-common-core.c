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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/args.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/servers-setup.h>

#include <irssi/src/core/special-vars.h>
#include <irssi/src/fe-common/core/fe-core-commands.h>
#include <irssi/src/fe-common/core/fe-queries.h>
#ifdef HAVE_CAPSICUM
#include <irssi/src/fe-common/core/fe-capsicum.h>
#endif
#include <irssi/src/fe-common/core/hilight-text.h>
#include <irssi/src/fe-common/core/command-history.h>
#include <irssi/src/fe-common/core/completion.h>
#include <irssi/src/fe-common/core/keyboard.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-common/core/fe-channels.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/window-activity.h>
#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/fe-common/core/windows-layout.h>
#include <irssi/src/fe-common/core/fe-recode.h>

#include <signal.h>

static char *autocon_server;
static char *autocon_password;
static int autocon_port;
static int no_autoconnect;
static char *cmdline_nick;
static char *cmdline_hostname;
GLogFunc logger_old;

void fe_core_log_init(void);
void fe_core_log_deinit(void);

void fe_exec_init(void);
void fe_exec_deinit(void);

void fe_expandos_init(void);
void fe_expandos_deinit(void);

void fe_help_init(void);
void fe_help_deinit(void);

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

void fe_tls_init(void);
void fe_tls_deinit(void);

void window_commands_init(void);
void window_commands_deinit(void);

static void sig_setup_changed(void);

static void sig_connected(SERVER_REC *server)
{
	MODULE_DATA_SET(server, g_new0(MODULE_SERVER_REC, 1));
}

static void sig_destroyed(SERVER_REC *server)
{
	void *data = MODULE_DATA(server);
	g_free(data);
	MODULE_DATA_UNSET(server);
}

static void sig_channel_created(CHANNEL_REC *channel)
{
	MODULE_DATA_SET(channel, g_new0(MODULE_CHANNEL_REC, 1));
}

static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	void *data = MODULE_DATA(channel);

	g_free(data);
	MODULE_DATA_UNSET(channel);
}

void fe_common_core_register_options(void)
{
	static GOptionEntry options[] = {
		{ "connect", 'c', 0, G_OPTION_ARG_STRING, &autocon_server, "Automatically connect to server/network", "SERVER" },
		{ "password", 'w', 0, G_OPTION_ARG_STRING, &autocon_password, "Autoconnect password", "PASSWORD" },
		{ "port", 'p', 0, G_OPTION_ARG_INT, &autocon_port, "Autoconnect port", "PORT" },
		{ "noconnect", '!', 0, G_OPTION_ARG_NONE, &no_autoconnect, "Disable autoconnecting", NULL },
		{ "nick", 'n', 0, G_OPTION_ARG_STRING, &cmdline_nick, "Specify nick to use", NULL },
		{ "hostname", 'h', 0, G_OPTION_ARG_STRING, &cmdline_hostname, "Specify host name to use", NULL },
		{ NULL }
	};

	autocon_server = NULL;
	autocon_password = NULL;
	autocon_port = 0;
	no_autoconnect = FALSE;
	cmdline_nick = NULL;
	cmdline_hostname = NULL;
	args_register(options);
}

void fe_common_core_init(void)
{
	const char *str;

	settings_add_bool("lookandfeel", "timestamps", TRUE);
	settings_add_level("lookandfeel", "timestamp_level", "ALL");
	settings_add_time("lookandfeel", "timestamp_timeout", "0");

	settings_add_level("lookandfeel", "beep_msg_level", "");
	settings_add_bool("lookandfeel", "beep_when_window_active", TRUE);
	settings_add_bool("lookandfeel", "beep_when_away", TRUE);

	settings_add_bool("lookandfeel", "hide_text_style", FALSE);
	settings_add_bool("lookandfeel", "hide_colors", FALSE);
	settings_add_bool("lookandfeel", "hide_server_tags", FALSE);

	settings_add_bool("lookandfeel", "use_status_window", TRUE);
	settings_add_bool("lookandfeel", "use_msgs_window", FALSE);
	g_get_charset(&str);
	settings_add_str("lookandfeel", "term_charset", str);
	settings_add_str("lookandfeel", "glib_log_domains", "all");
	themes_init();
        theme_register(fecommon_core_formats);

	command_history_init();
	completion_init();
	keyboard_init();
	printtext_init();
	formats_init();
        fe_exec_init();
        fe_expandos_init();
	fe_help_init();
	fe_ignore_init();
	fe_log_init();
	fe_modules_init();
	fe_server_init();
	fe_settings_init();
	fe_tls_init();
#ifdef HAVE_CAPSICUM
	fe_capsicum_init();
#endif
	windows_init();
	window_activity_init();
	window_commands_init();
	window_items_init();
	windows_layout_init();
	fe_core_commands_init();

        fe_channels_init();
        fe_queries_init();

	fe_messages_init();
	hilight_text_init();
	fe_ignore_messages_init();
	fe_recode_init();

	settings_check();

        signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
        signal_add_last("server destroyed", (SIGNAL_FUNC) sig_destroyed);
        signal_add_first("channel created", (SIGNAL_FUNC) sig_channel_created);
        signal_add_last("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	module_register("core", "fe");
}

void fe_common_core_deinit(void)
{
	hilight_text_deinit();
	command_history_deinit();
	completion_deinit();
	keyboard_deinit();
	printtext_deinit();
	formats_deinit();
        fe_exec_deinit();
        fe_expandos_deinit();
	fe_help_deinit();
	fe_ignore_deinit();
	fe_log_deinit();
	fe_modules_deinit();
	fe_server_deinit();
	fe_settings_deinit();
	fe_tls_deinit();
#ifdef HAVE_CAPSICUM
	fe_capsicum_deinit();
#endif
	windows_deinit();
	window_activity_deinit();
	window_commands_deinit();
	window_items_deinit();
	windows_layout_deinit();
	fe_core_commands_deinit();

        fe_channels_deinit();
        fe_queries_deinit();

	fe_messages_deinit();
	fe_ignore_messages_deinit();
	fe_recode_deinit();

        theme_unregister();
	themes_deinit();

        signal_remove("setup changed", (SIGNAL_FUNC) sig_setup_changed);
        signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
        signal_remove("server destroyed", (SIGNAL_FUNC) sig_destroyed);
        signal_remove("channel created", (SIGNAL_FUNC) sig_channel_created);
        signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	g_log_set_default_handler(logger_old, NULL);
}

static gboolean glib_domain_wanted(const char *domain)
{
	const char *domains;
	char *c, *cur;
	int len = 0;
	int print_it = 0; /* -1 for exclude, 0 for undecided, 1 for include */
	int incl;

	/* Go through each item in glib_log_domains setting to determine whether
	 * or not we want to print message from this domain */
	domains = settings_get_str("glib_log_domains");
	c = cur = (char *) domains;

	do {
		/* Advance through the string until we hit a space or the end */
		while (*cur != '\0' && *cur != ' ') {
			cur++;
			len++;
		}

		/* Handle '-' prefix */
		incl = 1;
		if (*c == '-') {
			incl = -1;
			c++;
			len--;
		}

		/* If we got a valid item, process it */
		if (len > 0 && (!strncmp(domain, c, len) || !strncasecmp("all", c, len) ||
		                !strncmp("*", c, len)))
			print_it = incl;

		/* Go past any spaces towards the next item */
		while (*cur == ' ')
			cur++;

		/* Move on beyond the item we just handled */
		c = cur;
		len = 0;
	} while (*c != '\0' && print_it != -1);

	return (print_it == 1);
}

static void i_log_func(const char *log_domain, GLogLevelFlags log_level, const char *message)
{
	const char *reason, *domain;

	switch (log_level) {
	case G_LOG_LEVEL_WARNING:
                reason = "warning";
                break;
	case G_LOG_LEVEL_CRITICAL:
                reason = "critical";
		break;
	case G_LOG_LEVEL_DEBUG:
		reason = "debug";
		break;
	case G_LOG_LEVEL_MESSAGE:
		reason = "message";
		break;
	case G_LOG_LEVEL_INFO:
		reason = "info";
		break;
	default:
		reason = "error";
                break;
	}

	/* If log_domain parameter is NULL, GLib means to tell us that this is
	 * meant to be some nebulous "default" log domain name. */
	domain = (log_domain ? log_domain : "default");

	/* Only print the message if we decided to */
	if (!glib_domain_wanted(domain))
		return;

	if (windows == NULL)
		fprintf(stderr, "GLib (%s) %s: %s\n", domain, reason, message);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_GLIB_ERROR, domain, reason,
		            message);
	}
}

#define MSGS_WINDOW_LEVELS (MSGLEVEL_MSGS|MSGLEVEL_ACTIONS|MSGLEVEL_DCCMSGS)

static void create_windows(void)
{
	WINDOW_REC *window;
	int have_status = settings_get_bool("use_status_window");

	window = window_find_name("(status)");
	if (have_status) {
		if (window == NULL) {
			window = window_create(NULL, TRUE);
			window_set_refnum(window, 1);
			window_set_name(window, "(status)");
			window_set_level(window, MSGLEVEL_ALL ^
					 (settings_get_bool("use_msgs_window") ?
					  MSGS_WINDOW_LEVELS : 0));
			window_set_immortal(window, TRUE);
		}
	} else {
		if (window != NULL) {
			window_set_name(window, NULL);
			window_set_level(window, 0);
			window_set_immortal(window, FALSE);
		}
	}

	window = window_find_name("(msgs)");
	if (settings_get_bool("use_msgs_window")) {
		if (window == NULL) {
			window = window_create(NULL, TRUE);
			window_set_refnum(window, have_status ? 2 : 1);
			window_set_name(window, "(msgs)");
			window_set_level(window, MSGS_WINDOW_LEVELS);
			window_set_immortal(window, TRUE);
		}
	} else {
		if (window != NULL) {
			window_set_name(window, NULL);
			window_set_level(window, 0);
			window_set_immortal(window, FALSE);
		}
	}

	if (windows == NULL) {
		/* we have to have at least one window.. */
                window = window_create(NULL, TRUE);
	}
}

static void autoconnect_servers(void)
{
	GSList *tmp, *chatnets;
	char *str;

	if (autocon_server != NULL) {
		/* connect to specified server */
		if (autocon_password == NULL)
			str = g_strdup_printf("%s %d", autocon_server, autocon_port);
		else
			str = g_strdup_printf("%s %d %s", autocon_server, autocon_port, autocon_password);

		signal_emit("command connect", 1, str);
		g_free(str);
		return;
	}

	if (no_autoconnect) {
		/* don't autoconnect */
		return;
	}

	/* connect to autoconnect servers */
	chatnets = NULL;
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (rec->autoconnect &&
		    (rec->chatnet == NULL ||
		     i_slist_find_icase_string(chatnets, rec->chatnet) == NULL)) {
			if (rec->chatnet != NULL) {
				chatnets = g_slist_append(chatnets, rec->chatnet);
				str = g_strdup_printf("-network %s %s %d", rec->chatnet, rec->address, rec->port);
			} else {
				str = g_strdup_printf("%s %d", rec->address, rec->port);
			}

			signal_emit("command connect", 1, str);
			g_free(str);
		}
	}

	g_slist_free(chatnets);
}

static void sig_setup_changed(void)
{
	static int firsttime = TRUE;
	static int status_window = FALSE, msgs_window = FALSE;
	int changed = FALSE;

	if (settings_get_bool("use_status_window") != status_window) {
		status_window = !status_window;
		changed = TRUE;
	}
	if (settings_get_bool("use_msgs_window") != msgs_window) {
		msgs_window = !msgs_window;
		changed = TRUE;
	}

	if (firsttime) {
		firsttime = FALSE;
		changed = TRUE;

		windows_layout_restore();
		if (windows != NULL)
			return;
	}

	if (changed)
		create_windows();
}

static void autorun_startup(void)
{
	char *path;
	GIOChannel *handle;
	GString *buf;
	gsize tpos;

	/* open ~/.irssi/startup and run all commands in it */
	path = g_strdup_printf("%s/startup", get_irssi_dir());
	handle = g_io_channel_new_file(path, "r", NULL);
	g_free(path);
	if (handle == NULL) {
		/* file not found */
		return;
	}

	g_io_channel_set_encoding(handle, NULL, NULL);
	buf = g_string_sized_new(512);
	while (g_io_channel_read_line_string(handle, buf, &tpos, NULL) == G_IO_STATUS_NORMAL) {
		buf->str[tpos] = '\0';
		if (buf->str[0] != '#') {
			eval_special_string(buf->str, "",
					    active_win->active_server,
					    active_win->active);
		}
	}
	g_string_free(buf, TRUE);

	g_io_channel_unref(handle);
}

void fe_common_core_finish_init(void)
{
	int setup_changed;

	signal_emit("irssi init read settings", 0);

#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

        setup_changed = FALSE;
	if (cmdline_nick != NULL && *cmdline_nick != '\0') {
		/* override nick found from setup */
		settings_set_str("nick", cmdline_nick);
		setup_changed = TRUE;
	}

	if (cmdline_hostname != NULL) {
		/* override host name found from setup */
		settings_set_str("hostname", cmdline_hostname);
		setup_changed = TRUE;
	}

	sig_setup_changed();
	signal_add_first("setup changed", (SIGNAL_FUNC) sig_setup_changed);

        /* _after_ windows are created.. */
	logger_old = g_log_set_default_handler((GLogFunc) i_log_func, NULL);

	if (setup_changed)
                signal_emit("setup changed", 0);

	autorun_startup();
	signal_emit("module autoload", 0);
	autoconnect_servers();
}

gboolean strarray_find_dest(char **array, const TEXT_DEST_REC *dest)
{
	WI_ITEM_REC *item;
	int server_tag_len, channel_type, query_type;
	char **tmp;

	channel_type = module_get_uniq_id_str("WINDOW ITEM TYPE", "CHANNEL");
	query_type = module_get_uniq_id_str("WINDOW ITEM TYPE", "QUERY");

	g_return_val_if_fail(array != NULL, FALSE);
	g_return_val_if_fail(dest != NULL, FALSE);
	g_return_val_if_fail(dest->window != NULL, FALSE);

	if (dest->target == NULL)
		return dest->window->name != NULL &&
			strarray_find(array, dest->window->name) != -1 ? TRUE : FALSE;

	item = window_item_find_window(dest->window, dest->server, dest->target);

	server_tag_len = dest->server_tag != NULL ? strlen(dest->server_tag) : 0;
	for (tmp = array; *tmp != NULL; tmp++) {
		char *str = *tmp;
		if (*str == '\0') {
			continue;
		}

		if (server_tag_len &&
		    g_ascii_strncasecmp(str, dest->server_tag, server_tag_len) == 0 &&
		    str[server_tag_len] == '/') {
			str += server_tag_len + 1;
		}

		if (g_strcmp0(str, "*") == 0 || g_strcmp0(str, "::all") == 0) {
			return TRUE;
		} else if (g_ascii_strcasecmp(str, dest->target) == 0) {
			return TRUE;
		} else if (item != NULL && item->type == query_type &&
		           g_strcmp0(str, dest->target[0] == '=' ? "::dccqueries" :
			             "::queries") == 0) {
			return TRUE;
		} else if (item != NULL && item->type == channel_type &&
			   g_strcmp0(str, "::channels") == 0) {
			return TRUE;
		}
	}

	return FALSE;
}
