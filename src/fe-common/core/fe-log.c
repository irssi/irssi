/*
 fe-log.c : irssi

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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/log.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/lib-config/iconfig.h>
#ifdef HAVE_CAPSICUM
#include <irssi/src/core/capsicum.h>
#endif

#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/fe-common-core.h>

#include <irssi/src/core/channels-setup.h>

/* close autologs after 5 minutes of inactivity */
#define AUTOLOG_INACTIVITY_CLOSE (60*5)

static int autolog_level;
static int log_server_time;
static int autoremove_tag;
static char *autolog_path;

static THEME_REC *log_theme;
static int skip_next_printtext;
static char *log_theme_name;

static char **autolog_ignore_targets;
static GTimeZone *utc;

static char *log_colorizer_strip(const char *str)
{
	return strip_codes(str);
}

static void log_add_targets(LOG_REC *log, const char *targets, const char *tag)
{
	char **tmp, **items;

	g_return_if_fail(log != NULL);
	g_return_if_fail(targets != NULL);

	items = g_strsplit(targets, " ", -1);

	for (tmp = items; *tmp != NULL; tmp++)
		log_item_add(log, LOG_ITEM_TARGET, *tmp, tag);

	g_strfreev(items);
}

/* SYNTAX: LOG OPEN [-noopen] [-autoopen] [-window] [-<server tag>]
                    [-targets <targets>] [-colors]
		    <fname> [<levels>] */
static void cmd_log_open(const char *data)
{
	SERVER_REC *server;
	GHashTable *optlist;
	char *targetarg, *fname, *levels, *servertag;
	void *free_arg;
	char window[MAX_INT_STRLEN];
	LOG_REC *log;
	int level;

	if (!cmd_get_params(data, &free_arg,
	                    2 | PARAM_FLAG_GETREST | PARAM_FLAG_UNKNOWN_OPTIONS |
	                        PARAM_FLAG_OPTIONS | PARAM_FLAG_STRIP_TRAILING_WS,
	                    "log open", &optlist, &fname, &levels))
		return;
	if (*fname == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	level = level2bits(levels, NULL);
	log = log_create_rec(fname, level != 0 ? level : MSGLEVEL_ALL);

	/* -<server tag> */
	server = cmd_options_get_server("log open", optlist, NULL);
	servertag = server == NULL ? NULL : server->tag;

	if (g_hash_table_lookup(optlist, "window")) {
		/* log by window ref# */
		targetarg = g_hash_table_lookup(optlist, "targets");
		if (targetarg == NULL || !is_numeric(targetarg, '\0')) {
			ltoa(window, active_win->refnum);
			targetarg = window;
		}
		log_item_add(log, LOG_ITEM_WINDOW_REFNUM, targetarg, servertag);
	} else {
		targetarg = g_hash_table_lookup(optlist, "targets");
		if (targetarg != NULL && *targetarg != '\0')
			log_add_targets(log, targetarg, servertag);
		else if (servertag != NULL)
			log_add_targets(log, "*", servertag);
	}

	if (g_hash_table_lookup(optlist, "autoopen"))
		log->autoopen = TRUE;

	if (g_hash_table_lookup(optlist, "colors") == NULL)
		log->colorizer = log_colorizer_strip;

	log_update(log);

	if (log->handle == -1 && g_hash_table_lookup(optlist, "noopen") == NULL) {
		/* start logging */
		if (log_start_logging(log)) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_OPENED, fname);
		} else {
			log_close(log);
		}
	}

	cmd_params_free(free_arg);
}

static LOG_REC *log_find_from_data(const char *data)
{
	GSList *tmp;

	if (!is_numeric(data, ' '))
		return log_find(data);

	/* with index number */
	tmp = g_slist_nth(logs, atoi(data)-1);
	return tmp == NULL ? NULL : tmp->data;
}

/* SYNTAX: LOG CLOSE <id>|<file> */
static void cmd_log_close(const char *data)
{
	LOG_REC *log;

	log = log_find_from_data(data);
	if (log == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_LOG_NOT_OPEN, data);
	else {
		log_close(log);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_CLOSED, data);
	}
}

/* SYNTAX: LOG START <id>|<file> */
static void cmd_log_start(const char *data)
{
	LOG_REC *log;

	log = log_find_from_data(data);
	if (log != NULL) {
		log_start_logging(log);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_OPENED, data);
	}
}

/* SYNTAX: LOG STOP <id>|<file> */
static void cmd_log_stop(const char *data)
{
	LOG_REC *log;

	log = log_find_from_data(data);
	if (log == NULL || log->handle == -1)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_LOG_NOT_OPEN, data);
	else {
		log_stop_logging(log);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_CLOSED, data);
	}
}

static char *log_items_get_list(LOG_REC *log)
{
	GSList *tmp;
	GString *str;
	char *ret;
	LOG_ITEM_REC *rec = NULL;

	g_return_val_if_fail(log != NULL, NULL);
	g_return_val_if_fail(log->items != NULL, NULL);

	str = g_string_new(NULL);
	for (tmp = log->items; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		g_string_append_printf(str, "%s, ", rec->name);
	}
	g_string_truncate(str, str->len-2);
	if(rec->servertag != NULL)
		g_string_append_printf(str, " (%s)", rec->servertag);

	ret = g_string_free_and_steal(str);
	return ret;
}

static void cmd_log_list(void)
{
	GSList *tmp;
	char *levelstr, *items;
	int index;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_LOG_LIST_HEADER);
	for (tmp = logs, index = 1; tmp != NULL; tmp = tmp->next, index++) {
		LOG_REC *rec = tmp->data;

		levelstr = bits2level(rec->level);
		items = rec->items == NULL ? NULL : log_items_get_list(rec);

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_LOG_LIST, index, rec->fname,
		            items != NULL ? items : "", levelstr, rec->autoopen ? " -autoopen" : "",
		            rec->handle != -1 ? " active" : "");

		g_free_not_null(items);
		g_free(levelstr);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_LOG_LIST_FOOTER);
}

static void cmd_log(const char *data, SERVER_REC *server, void *item)
{
	if (*data == '\0')
		cmd_log_list();
	else
		command_runsub("log", data, server, item);
}

static LOG_REC *logs_find_item(int type, const char *item, const char *servertag,
                               LOG_ITEM_REC **ret_item)
{
	LOG_ITEM_REC *logitem;
	GSList *tmp;

	for (tmp = logs; tmp != NULL; tmp = tmp->next) {
		LOG_REC *log = tmp->data;

		if (type == LOG_ITEM_TARGET && log->temp == 0) continue;
		logitem = log_item_find(log, type, item, servertag);
		if (logitem != NULL) {
			if (ret_item != NULL) *ret_item = logitem;
			return log;
		}
	}

	return NULL;
}

/* SYNTAX: WINDOW LOG on|off|toggle [<filename>] */
static void cmd_window_log(const char *data)
{
	LOG_REC *log;
	char *set, *fname, window[MAX_INT_STRLEN];
	void *free_arg;
	int open_log, close_log;

	if (!cmd_get_params(data, &free_arg, 2, &set, &fname))
		return;

	ltoa(window, active_win->refnum);
	log = logs_find_item(LOG_ITEM_WINDOW_REFNUM, window, NULL, NULL);

	open_log = close_log = FALSE;
	if (g_ascii_strcasecmp(set, "ON") == 0)
		open_log = TRUE;
	else if (g_ascii_strcasecmp(set, "OFF") == 0) {
		close_log = TRUE;
	} else if (g_ascii_strcasecmp(set, "TOGGLE") == 0) {
		open_log = log == NULL;
		close_log = log != NULL;
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_NOT_TOGGLE);
		cmd_params_free(free_arg);
		return;
	}

	if (open_log && log == NULL) {
		/* irc.log.<windowname> or irc.log.Window<ref#> */
		fname = *fname != '\0' ? g_strdup(fname) :
			g_strdup_printf("~/irc.log.%s%s",
					active_win->name != NULL ? active_win->name : "Window",
					active_win->name != NULL ? "" : window);
		log = log_create_rec(fname, MSGLEVEL_ALL);
		log->colorizer = log_colorizer_strip;
		log_item_add(log, LOG_ITEM_WINDOW_REFNUM, window, NULL);
		log_update(log);
		g_free(fname);
	}

	if (open_log && log != NULL) {
		log_start_logging(log);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_OPENED, log->fname);
	} else if (close_log && log != NULL && log->handle != -1) {
		log_stop_logging(log);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_CLOSED, log->fname);
	}

	cmd_params_free(free_arg);
}

/* Create log file entry to window, but don't start logging */
/* SYNTAX: WINDOW LOGFILE <file> */
static void cmd_window_logfile(const char *data)
{
	LOG_REC *log;
	char window[MAX_INT_STRLEN];
	void *free_arg;
	char *fname;

	if (!cmd_get_params(data, &free_arg, 1, &fname)) {
		return;
	}

	if (!fname || strlen(fname) == 0) {
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	}

	ltoa(window, active_win->refnum);
	log = logs_find_item(LOG_ITEM_WINDOW_REFNUM, window, NULL, NULL);

	if (log != NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_WINDOWLOG_FILE_LOGGING);
		cmd_params_free(free_arg);
		return;
	}

	log = log_create_rec(fname, MSGLEVEL_ALL);
	log->colorizer = log_colorizer_strip;
	log_item_add(log, LOG_ITEM_WINDOW_REFNUM, window, NULL);
	log_update(log);

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_WINDOWLOG_FILE, data);

	cmd_params_free(free_arg);
}

/* window's refnum changed - update the logs to log the new window refnum */
static void sig_window_refnum_changed(WINDOW_REC *window, gpointer old_refnum)
{
	char winnum[MAX_INT_STRLEN];
	LOG_REC *log;
	LOG_ITEM_REC *item;

	ltoa(winnum, GPOINTER_TO_INT(old_refnum));
	log = logs_find_item(LOG_ITEM_WINDOW_REFNUM, winnum, NULL, &item);

	if (log != NULL) {
		ltoa(winnum, window->refnum);

		g_free(item->name);
		item->name = g_strdup(winnum);
	}
}

static void sig_server_disconnected(SERVER_REC *server)
{
	LOG_ITEM_REC *logitem;
	GSList *tmp, *next;

	for (tmp = logs; tmp != NULL; tmp = next) {
		LOG_REC *log = tmp->data;
		next = tmp->next;

		if (!log->temp || log->items == NULL)
			continue;

		logitem = log->items->data;
		if (logitem->type == LOG_ITEM_TARGET && logitem->servertag != NULL &&
		    g_ascii_strcasecmp(logitem->servertag, server->tag) == 0 &&
		    server_ischannel(
		        server, logitem->name)) /* kludge again.. so we won't close dcc chats */
			log_close(log);
	}
}

static void autologs_close_all(void)
{
	GSList *tmp, *next;

	for (tmp = logs; tmp != NULL; tmp = next) {
		LOG_REC *rec = tmp->data;

		next = tmp->next;
		if (rec->temp) log_close(rec);
	}
}

/* '%' -> '%%', badness -> '_' */
static char *escape_target(const char *target)
{
	char *str, *p;

	p = str = g_malloc(strlen(target)*2+1);
	while (*target != '\0') {
		if (strchr("/\\|*?\"<>:", *target))
			*p++ = '_';
		else {
			if (*target == '%')
				*p++ = '%';
			*p++ = *target;
		}

		target++;
	}
	*p = '\0';

	return str;
}

static void autolog_open(SERVER_REC *server, const char *server_tag, const char *target)
{
	LOG_REC *log;
	char *fname, *dir, *fixed_target, *params;

	log = logs_find_item(LOG_ITEM_TARGET, target, server_tag, NULL);
	if (log != NULL && !log->failed) {
		log_start_logging(log);
		return;
	}

	/* '/' -> '_' - don't even accidentally try to log to
	   #../../../file if you happen to join to such channel..
	   similar for some characters that are metacharacters
	   and/or illegal in Windows filenames.

	   '%' -> '%%' - so strftime() won't mess with them */
	fixed_target = escape_target(target);
	if (CHAT_PROTOCOL(server)->case_insensitive)
		ascii_strdown(fixed_target);

	/* $0 = target, $1 = server tag */
	params = g_strconcat(fixed_target, " ", server_tag, NULL);
	g_free(fixed_target);

	fname = parse_special_string(autolog_path, server, NULL, params, NULL, 0);
	g_free(params);

	if (log_find(fname) == NULL) {
		log = log_create_rec(fname, autolog_level);
		if (!settings_get_bool("autolog_colors"))
			log->colorizer = log_colorizer_strip;
		log_item_add(log, LOG_ITEM_TARGET, target, server_tag);

		dir = g_path_get_dirname(log->real_fname);
#ifdef HAVE_CAPSICUM
		capsicum_mkdir_with_parents_wrapper(dir, log_dir_create_mode);
#else
		g_mkdir_with_parents(dir, log_dir_create_mode);
#endif
		g_free(dir);

		log->temp = TRUE;
		log_update(log);
		log_start_logging(log);
	}
	g_free(fname);
}

static void autolog_open_check(TEXT_DEST_REC *dest)
{
	const char *deftarget;
	SERVER_REC *server = dest->server;
	const char *server_tag = dest->server_tag;
	const char *target = dest->target;
	int level = dest->level;

	/* FIXME: kind of a kludge, but we don't want to reopen logs when
	   we're parting the channel with /WINDOW CLOSE.. Maybe a small
	   timeout would be nice instead of immediately closing the log file
	   after "window item destroyed" */
	if (level == MSGLEVEL_PARTS || (autolog_level & level) == 0 || target == NULL ||
	    *target == '\0')
		return;

	deftarget = server ? server->nick : "unknown";

	/* log only channels that have been saved to the config */
	if (settings_get_bool("autolog_only_saved_channels") && IS_CHANNEL(window_item_find(server, target))
		&& channel_setup_find(target, server_tag) == NULL)
		return;

	if (autolog_ignore_targets != NULL && strarray_find_dest(autolog_ignore_targets, dest))
		return;

	if (target != NULL)
		autolog_open(server, server_tag, g_strcmp0(target, "*") ? target : deftarget);
}

static void log_single_line(WINDOW_REC *window, const char *server_tag, const char *target,
                            int level, time_t t, const char *text)
{
	char windownum[MAX_INT_STRLEN];
	LOG_REC *log;

	if (window != NULL) {
		/* save to log created with /WINDOW LOG */
		ltoa(windownum, window->refnum);
		log = logs_find_item(LOG_ITEM_WINDOW_REFNUM, windownum, NULL, NULL);
		if (log != NULL)
			log_write_rec(log, text, level, t);
	}

	log_file_write(server_tag, target, level, t, text, FALSE);
}

static void log_line(TEXT_DEST_REC *dest, const char *text)
{
	char **lines, **tmp;
	time_t t = (time_t) -1;

	if (dest->level == MSGLEVEL_NEVER)
		return;

	/* let autolog open the log records */
	autolog_open_check(dest);

	if (logs == NULL)
		return;

	/* text may contain one or more lines, log wants to eat them one
	   line at a time */
	lines = g_strsplit(text, "\n", -1);
	if (log_server_time && dest->meta != NULL) {
		char *val;
		if ((val = g_hash_table_lookup(dest->meta, "time")) != NULL) {
			GDateTime *time;
			if ((time = g_date_time_new_from_iso8601(val, utc)) != NULL) {
				t = g_date_time_to_unix(time);
				g_date_time_unref(time);
			}
		}
	}
	for (tmp = lines; *tmp != NULL; tmp++)
		log_single_line(dest->window, dest->server_tag, dest->target, dest->level, t, *tmp);
	g_strfreev(lines);
}

static void sig_printtext(TEXT_DEST_REC *dest, const char *text, const char *stripped)
{
	if (skip_next_printtext) {
		skip_next_printtext = FALSE;
		return;
	}

	log_line(dest, text);
}

static void sig_print_format(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest,
                             void *formatnum, char **args)
{
	char *str, *linestart, *tmp;

	if (log_theme == NULL) {
		/* theme isn't loaded for some reason (/reload destroys it),
		   reload it. */
		log_theme = theme_load(log_theme_name);
		if (log_theme == NULL) return;
	}

	if (theme == log_theme)
		return;

	str = format_get_text_theme_charargs(log_theme, module, dest, GPOINTER_TO_INT(formatnum),
	                                     args);
	if (str != NULL && *str != '\0') {
		skip_next_printtext = TRUE;

		/* add the line start format */
		linestart = format_get_level_tag(log_theme, dest);
		tmp = str;
		str = format_add_linestart(tmp, linestart);
		g_free_not_null(linestart);
		g_free(tmp);

		/* strip colors from text, log it. */
		log_line(dest, str);
	}
	g_free(str);

}

static int sig_autoremove(void)
{
	SERVER_REC *server;
	LOG_ITEM_REC *logitem;
	GSList *tmp, *next;
	time_t removetime;

	removetime = time(NULL) - AUTOLOG_INACTIVITY_CLOSE;
	for (tmp = logs; tmp != NULL; tmp = next) {
		LOG_REC *log = tmp->data;

		next = tmp->next;

		if (!log->temp || log->last > removetime || log->items == NULL)
			continue;

		/* Close only logs with private messages */
		logitem = log->items->data;
		if (logitem->servertag == NULL)
			continue;

		server = server_find_tag(logitem->servertag);
		if (logitem->type == LOG_ITEM_TARGET && server != NULL &&
		    !server_ischannel(server, logitem->name))
			log_close(log);
	}
	return 1;
}

static void sig_window_item_remove(WINDOW_REC *window, WI_ITEM_REC *item)
{
	LOG_REC *log;

	log = logs_find_item(LOG_ITEM_TARGET, item->visible_name,
	                     item->server == NULL ? NULL : item->server->tag, NULL);
	if (log != NULL && log->temp)
		log_close(log);
}

static void sig_log_locked(LOG_REC *log)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_LOG_LOCKED, log->real_fname);
}

static void sig_log_create_failed(LOG_REC *log)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_LOG_CREATE_FAILED, log->real_fname,
	            g_strerror(errno));
}

static void sig_log_new(LOG_REC *log)
{
	if (!settings_get_bool("awaylog_colors") &&
	    g_strcmp0(log->fname, settings_get_str("awaylog_file")) == 0)
		log->colorizer = log_colorizer_strip;
}

static void sig_log_config_read(LOG_REC *log, CONFIG_NODE *node)
{
	if (!config_node_get_bool(node, "colors", FALSE))
		log->colorizer = log_colorizer_strip;
}

static void sig_log_config_save(LOG_REC *log, CONFIG_NODE *node)
{
	if (log->colorizer == NULL)
		iconfig_node_set_bool(node, "colors", TRUE);
	else
		iconfig_node_set_str(node, "colors", NULL);
}

static void sig_awaylog_show(LOG_REC *log, gpointer pmsgs, gpointer pfilepos)
{
	char *str;
	int msgs, filepos;

	msgs = GPOINTER_TO_INT(pmsgs);
	filepos = GPOINTER_TO_INT(pfilepos);

	if (msgs == 0)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_NO_AWAY_MSGS, log->real_fname);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_LOG_AWAY_MSGS, log->real_fname, msgs);

		str = g_strdup_printf("\"%s\" %d", log->real_fname, filepos);
		signal_emit("command cat", 1, str);
		g_free(str);
	}
}

static void sig_theme_destroyed(THEME_REC *theme)
{
	if (theme == log_theme)
		log_theme = NULL;
}

static void read_settings(void)
{
	int old_autolog = autolog_level;

	g_free_not_null(autolog_path);
	autolog_path = g_strdup(settings_get_str("autolog_path"));

	autolog_level = !settings_get_bool("autolog") ? 0 :
		settings_get_level("autolog_level");

	if (old_autolog && !autolog_level)
		autologs_close_all();

	/* write to log files with different theme? */
	if (log_theme_name != NULL)
		signal_remove("print format", (SIGNAL_FUNC) sig_print_format);

	g_free_not_null(log_theme_name);
	log_theme_name = g_strdup(settings_get_str("log_theme"));

	if (*log_theme_name == '\0') {
		g_free(log_theme_name);
		log_theme_name = NULL;
	}
	else
		signal_add("print format", (SIGNAL_FUNC) sig_print_format);

	log_theme = log_theme_name == NULL ? NULL :
		theme_load(log_theme_name);

	if (autolog_ignore_targets != NULL)
		g_strfreev(autolog_ignore_targets);

	autolog_ignore_targets = g_strsplit(settings_get_str("autolog_ignore_targets"), " ", -1);

	log_server_time = settings_get_choice("log_server_time");
	if (log_server_time == 2) {
		SETTINGS_REC *rec = settings_get_record("show_server_time");
		if (rec != NULL)
			log_server_time = settings_get_bool("show_server_time");
	}
}

void fe_log_init(void)
{
	autoremove_tag = g_timeout_add(60000, (GSourceFunc) sig_autoremove, NULL);
	skip_next_printtext = FALSE;
	utc = g_time_zone_new_utc();

	settings_add_bool("log", "awaylog_colors", TRUE);
	settings_add_bool("log", "autolog", FALSE);
	settings_add_bool("log", "autolog_colors", FALSE);
	settings_add_bool("log", "autolog_only_saved_channels", FALSE);
	settings_add_choice("log", "log_server_time", 2, "off;on;auto");
	settings_add_str("log", "autolog_path", "~/irclogs/$tag/$0.log");
	settings_add_level("log", "autolog_level", "all -crap -clientcrap -ctcps");
	settings_add_str("log", "log_theme", "");
	settings_add_str("log", "autolog_ignore_targets", "");

	autolog_level = 0;
	log_theme_name = NULL;
	read_settings();

	command_bind("log", NULL, (SIGNAL_FUNC) cmd_log);
	command_bind("log open", NULL, (SIGNAL_FUNC) cmd_log_open);
	command_bind("log close", NULL, (SIGNAL_FUNC) cmd_log_close);
	command_bind("log start", NULL, (SIGNAL_FUNC) cmd_log_start);
	command_bind("log stop", NULL, (SIGNAL_FUNC) cmd_log_stop);
	command_bind("window log", NULL, (SIGNAL_FUNC) cmd_window_log);
	command_bind("window logfile", NULL, (SIGNAL_FUNC) cmd_window_logfile);
	signal_add_first("print text", (SIGNAL_FUNC) sig_printtext);
	signal_add("window item remove", (SIGNAL_FUNC) sig_window_item_remove);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_window_refnum_changed);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("log locked", (SIGNAL_FUNC) sig_log_locked);
	signal_add("log create failed", (SIGNAL_FUNC) sig_log_create_failed);
	signal_add("log new", (SIGNAL_FUNC) sig_log_new);
	signal_add("log config read", (SIGNAL_FUNC) sig_log_config_read);
	signal_add("log config save", (SIGNAL_FUNC) sig_log_config_save);
	signal_add("awaylog show", (SIGNAL_FUNC) sig_awaylog_show);
	signal_add("theme destroyed", (SIGNAL_FUNC) sig_theme_destroyed);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	command_set_options("log open", "noopen autoopen -targets window colors");
}

void fe_log_deinit(void)
{
	g_source_remove(autoremove_tag);
	if (log_theme_name != NULL)
		signal_remove("print format", (SIGNAL_FUNC) sig_print_format);

	command_unbind("log", (SIGNAL_FUNC) cmd_log);
	command_unbind("log open", (SIGNAL_FUNC) cmd_log_open);
	command_unbind("log close", (SIGNAL_FUNC) cmd_log_close);
	command_unbind("log start", (SIGNAL_FUNC) cmd_log_start);
	command_unbind("log stop", (SIGNAL_FUNC) cmd_log_stop);
	command_unbind("window log", (SIGNAL_FUNC) cmd_window_log);
	command_unbind("window logfile", (SIGNAL_FUNC) cmd_window_logfile);
	signal_remove("print text", (SIGNAL_FUNC) sig_printtext);
	signal_remove("window item remove", (SIGNAL_FUNC) sig_window_item_remove);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_window_refnum_changed);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("log locked", (SIGNAL_FUNC) sig_log_locked);
	signal_remove("log create failed", (SIGNAL_FUNC) sig_log_create_failed);
	signal_remove("log new", (SIGNAL_FUNC) sig_log_new);
	signal_remove("log config read", (SIGNAL_FUNC) sig_log_config_read);
	signal_remove("log config save", (SIGNAL_FUNC) sig_log_config_save);
	signal_remove("awaylog show", (SIGNAL_FUNC) sig_awaylog_show);
	signal_remove("theme destroyed", (SIGNAL_FUNC) sig_theme_destroyed);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	if (autolog_ignore_targets != NULL)
		g_strfreev(autolog_ignore_targets);

	g_time_zone_unref(utc);
	g_free_not_null(autolog_path);
	g_free_not_null(log_theme_name);
}
