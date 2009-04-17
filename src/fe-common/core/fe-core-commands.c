/*
 fe-core-commands.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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

#include "core.h"
#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"
#include "irssi-version.h"
#include "servers.h"

#include "fe-windows.h"
#include "printtext.h"

#define PASTE_CHECK_SPEED 200 /* 0.2 sec */

static int ret_texts[] = {
	TXT_OPTION_UNKNOWN,
	TXT_OPTION_AMBIGUOUS,
	TXT_OPTION_MISSING_ARG,
	TXT_COMMAND_UNKNOWN,
	TXT_COMMAND_AMBIGUOUS,
        -1,
	TXT_NOT_ENOUGH_PARAMS,
	TXT_NOT_CONNECTED,
	TXT_NOT_JOINED,
	TXT_CHAN_NOT_FOUND,
	TXT_CHAN_NOT_SYNCED,
        TXT_ILLEGAL_PROTO,
	TXT_NOT_GOOD_IDEA,
        TXT_INVALID_TIME,
        TXT_INVALID_CHARSET,
        TXT_EVAL_MAX_RECURSE,
        TXT_PROGRAM_NOT_FOUND
};

int command_hide_output;

/* keep the whole command line here temporarily. we need it in
   "default command" event handler, but there we don't know if the start of
   the line had one or two command chars, and which one.. */
static const char *current_cmdline;

static GTimeVal time_command_last, time_command_now;
static int last_command_cmd, command_cmd;

/* SYNTAX: ECHO [-current] [-window <name>] [-level <level>] <text> */
static void cmd_echo(const char *data, void *server, WI_ITEM_REC *item)
{
        WINDOW_REC *window;
	GHashTable *optlist;
	char *msg, *levelstr, *winname;
	void *free_arg;
	int level;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST, "echo", &optlist, &msg))
		return;

        levelstr = g_hash_table_lookup(optlist, "level");
	level = levelstr == NULL ? 0 :
		level2bits(g_hash_table_lookup(optlist, "level"), NULL);
	if (level == 0) level = MSGLEVEL_CRAP;

	winname = g_hash_table_lookup(optlist, "window");
	window = winname == NULL ? NULL :
		is_numeric(winname, '\0') ?
		window_find_refnum(atoi(winname)) :
		window_find_item(NULL, winname);
	if (window == NULL) window = active_win;

	printtext_window(window, level, "%s", msg);
	cmd_params_free(free_arg);
}

/* SYNTAX: VERSION */
static void cmd_version(char *data)
{
	char time[10];

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
                g_snprintf(time, sizeof(time), "%04d", IRSSI_VERSION_TIME);
		printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			  "Client: "PACKAGE_TARNAME" " PACKAGE_VERSION" (%d %s)",
			  IRSSI_VERSION_DATE, time);
	}
}

/* SYNTAX: CAT <file> */
static void cmd_cat(const char *data)
{
	char *fname, *fposstr;
	void *free_arg;
	int fpos;
	GIOChannel *handle;
	GString *buf;
	gsize tpos;

	if (!cmd_get_params(data, &free_arg, 2, &fname, &fposstr))
		return;

	fname = convert_home(fname);
	fpos = atoi(fposstr);
        cmd_params_free(free_arg);

	handle = g_io_channel_new_file(fname, "r", NULL);
	g_free(fname);

	if (handle == NULL) {
		/* file not found */
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "%s", g_strerror(errno));
		return;
	}

	g_io_channel_set_encoding(handle, NULL, NULL);
	g_io_channel_seek_position(handle, fpos, G_SEEK_SET, NULL);
	buf = g_string_sized_new(512);
	while (g_io_channel_read_line_string(handle, buf, &tpos, NULL) == G_IO_STATUS_NORMAL) {
		buf->str[tpos] = '\0';
		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP |
			  MSGLEVEL_NEVER, "%s", buf->str);
	}
	g_string_free(buf, TRUE);

	g_io_channel_unref(handle);
}

/* SYNTAX: BEEP */
static void cmd_beep(void)
{
        signal_emit("beep", 0);
}

static void cmd_nick(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);

	if (*data != '\0') return;
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	/* display current nick */
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_YOUR_NICK, server->nick);
	signal_stop();
}

/* SYNTAX: UPTIME */
static void cmd_uptime(char *data)
{
	long uptime;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
		uptime = time(NULL) - client_start_time;
		printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			  "Uptime: %ldd %ldh %ldm %lds",
			  uptime/3600/24, uptime/3600%24,
			  uptime/60%60, uptime%60);
	}
}

static void sig_stop(void)
{
	signal_stop();
}

static void event_command(const char *data)
{
	const char *cmdchar;

	/* save current command line */
	current_cmdline = data;

        /* for detecting if we're pasting text */
	time_command_last = time_command_now;
	last_command_cmd = command_cmd;

	g_get_current_time(&time_command_now);
	command_cmd = *data != '\0' &&
		strchr(settings_get_str("cmdchars"), *data) != NULL;

	/* /^command hides the output of the command */
	cmdchar = *data == '\0' ? NULL :
		strchr(settings_get_str("cmdchars"), *data);
	if (cmdchar != NULL && (data[1] == '^' ||
				(data[1] == *cmdchar && data[2] == '^'))
			    && !command_hide_output++) {
		signal_add_first("print starting", (SIGNAL_FUNC) sig_stop);
		signal_add_first("print format", (SIGNAL_FUNC) sig_stop);
		signal_add_first("print text", (SIGNAL_FUNC) sig_stop);
	}
}

static void event_command_last(const char *data)
{
	if (command_hide_output && !--command_hide_output) {
		signal_remove("print starting", (SIGNAL_FUNC) sig_stop);
		signal_remove("print format", (SIGNAL_FUNC) sig_stop);
		signal_remove("print text", (SIGNAL_FUNC) sig_stop);
	}
}

static void event_default_command(const char *data, void *server,
				  WI_ITEM_REC *item)
{
	const char *cmdchars, *ptr;
	char *cmd, *p;
	long diff;

	cmdchars = settings_get_str("cmdchars");

	ptr = data;
	while (*ptr != '\0' && *ptr != ' ') {
		if (strchr(cmdchars, *ptr)) {
			/* command character inside command .. we probably
			   want to send this text to channel. for example
			   when pasting a path /usr/bin/xxx. */
			signal_emit("send text", 3, current_cmdline, server, item);
			return;
		}
		ptr++;
	}

	/* maybe we're copy+pasting text? check how long it was since the
	   last line */
	diff = get_timeval_diff(&time_command_now, &time_command_last);
	if (item != NULL && !last_command_cmd && diff < PASTE_CHECK_SPEED) {
		signal_emit("send text", 3, current_cmdline, active_win->active_server, active_win->active);
		command_cmd = FALSE;
		return;
	}

	/* get the command part of the line, send "error command" signal */
	cmd = g_strdup(data);
	p = strchr(cmd, ' ');
	if (p != NULL) *p = '\0';

	signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_UNKNOWN), cmd);

	g_free(cmd);
}

static void event_cmderror(void *errorp, const char *arg)
{
	int error;

	error = GPOINTER_TO_INT(errorp);
	if (error == CMDERR_ERRNO) {
                /* errno is special */
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", g_strerror(errno));
	} else {
                /* others */
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, ret_texts[error + -CMDERR_OPTION_UNKNOWN], arg);
	}
}

static void event_list_subcommands(const char *command)
{
        GSList *tmp;
        GString *str;
	int len;

	str = g_string_new(NULL);

        len = strlen(command);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_strncasecmp(rec->cmd, command, len) == 0 &&
		    rec->cmd[len] == ' ' &&
		    strchr(rec->cmd+len+1, ' ') == NULL) {
                        g_string_append_printf(str, "%s ", rec->cmd+len+1);
		}
	}

	if (str->len != 0) {
		g_string_truncate(str, str->len-1);
                printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", str->str);
	}

        g_string_free(str, TRUE);
}

void fe_core_commands_init(void)
{
	command_hide_output = 0;

	command_cmd = FALSE;
	memset(&time_command_now, 0, sizeof(GTimeVal));

	command_bind("echo", NULL, (SIGNAL_FUNC) cmd_echo);
	command_bind("version", NULL, (SIGNAL_FUNC) cmd_version);
	command_bind("cat", NULL, (SIGNAL_FUNC) cmd_cat);
	command_bind("beep", NULL, (SIGNAL_FUNC) cmd_beep);
	command_bind("uptime", NULL, (SIGNAL_FUNC) cmd_uptime);
	command_bind_first("nick", NULL, (SIGNAL_FUNC) cmd_nick);

	signal_add("send command", (SIGNAL_FUNC) event_command);
	signal_add_last("send command", (SIGNAL_FUNC) event_command_last);
	signal_add("default command", (SIGNAL_FUNC) event_default_command);
	signal_add("error command", (SIGNAL_FUNC) event_cmderror);
	signal_add("list subcommands", (SIGNAL_FUNC) event_list_subcommands);

	command_set_options("echo", "current +level +window");
}

void fe_core_commands_deinit(void)
{
	command_unbind("echo", (SIGNAL_FUNC) cmd_echo);
	command_unbind("version", (SIGNAL_FUNC) cmd_version);
	command_unbind("cat", (SIGNAL_FUNC) cmd_cat);
	command_unbind("beep", (SIGNAL_FUNC) cmd_beep);
	command_unbind("uptime", (SIGNAL_FUNC) cmd_uptime);
	command_unbind("nick", (SIGNAL_FUNC) cmd_nick);

	signal_remove("send command", (SIGNAL_FUNC) event_command);
	signal_remove("send command", (SIGNAL_FUNC) event_command_last);
	signal_remove("default command", (SIGNAL_FUNC) event_default_command);
	signal_remove("error command", (SIGNAL_FUNC) event_cmderror);
	signal_remove("list subcommands", (SIGNAL_FUNC) event_list_subcommands);
}
