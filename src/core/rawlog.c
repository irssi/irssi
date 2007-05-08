/*
 rawlog.c : irssi

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
#include "rawlog.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "write-buffer.h"
#include "settings.h"

#include "servers.h"

static int rawlog_lines;
static int signal_rawlog;
static int log_file_create_mode;

RAWLOG_REC *rawlog_create(void)
{
	RAWLOG_REC *rec;

	rec = g_new0(RAWLOG_REC, 1);
        return rec;
}

void rawlog_destroy(RAWLOG_REC *rawlog)
{
	g_return_if_fail(rawlog != NULL);

	g_slist_foreach(rawlog->lines, (GFunc) g_free, NULL);
	g_slist_free(rawlog->lines);

	if (rawlog->logging) {
		write_buffer_flush();
		close(rawlog->handle);
	}
	g_free(rawlog);
}

/* NOTE! str must be dynamically allocated and must not be freed after! */
static void rawlog_add(RAWLOG_REC *rawlog, char *str)
{
	if (rawlog->nlines < rawlog_lines || rawlog_lines <= 2)
		rawlog->nlines++;
	else {
		g_free(rawlog->lines->data);
		rawlog->lines = g_slist_remove(rawlog->lines,
					       rawlog->lines->data);
	}

	if (rawlog->logging) {
		write_buffer(rawlog->handle, str, strlen(str));
		write_buffer(rawlog->handle, "\n", 1);
	}

	rawlog->lines = g_slist_append(rawlog->lines, str);
	signal_emit_id(signal_rawlog, 2, rawlog, str);
}

void rawlog_input(RAWLOG_REC *rawlog, const char *str)
{
	g_return_if_fail(rawlog != NULL);
	g_return_if_fail(str != NULL);

	rawlog_add(rawlog, g_strdup_printf(">> %s", str));
}

void rawlog_output(RAWLOG_REC *rawlog, const char *str)
{
	g_return_if_fail(rawlog != NULL);
	g_return_if_fail(str != NULL);

	rawlog_add(rawlog, g_strdup_printf("<< %s", str));
}

void rawlog_redirect(RAWLOG_REC *rawlog, const char *str)
{
	g_return_if_fail(rawlog != NULL);
	g_return_if_fail(str != NULL);

	rawlog_add(rawlog, g_strdup_printf("--> %s", str));
}

static void rawlog_dump(RAWLOG_REC *rawlog, int f)
{
	GSList *tmp;

	for (tmp = rawlog->lines; tmp != NULL; tmp = tmp->next) {
		write(f, tmp->data, strlen((char *) tmp->data));
		write(f, "\n", 1);
	}
}

void rawlog_open(RAWLOG_REC *rawlog, const char *fname)
{
	char *path;

        g_return_if_fail(rawlog != NULL);
	g_return_if_fail(fname != NULL);

	if (rawlog->logging)
		return;

	path = convert_home(fname);
	rawlog->handle = open(path, O_WRONLY | O_APPEND | O_CREAT,
			      log_file_create_mode);
	g_free(path);

	rawlog_dump(rawlog, rawlog->handle);
	rawlog->logging = rawlog->handle != -1;
}

void rawlog_close(RAWLOG_REC *rawlog)
{
	if (rawlog->logging) {
		write_buffer_flush();
		close(rawlog->handle);
		rawlog->logging = 0;
	}
}

void rawlog_save(RAWLOG_REC *rawlog, const char *fname)
{
	char *path;
	int f;

	path = convert_home(fname);
	f = open(path, O_WRONLY | O_APPEND | O_CREAT, log_file_create_mode);
	g_free(path);

	rawlog_dump(rawlog, f);
	close(f);
}

void rawlog_set_size(int lines)
{
	rawlog_lines = lines;
}

static void read_settings(void)
{
	rawlog_set_size(settings_get_int("rawlog_lines"));
	log_file_create_mode = octal2dec(settings_get_int("log_create_mode"));
}

static void cmd_rawlog(const char *data, SERVER_REC *server, void *item)
{
	command_runsub("rawlog", data, server, item);
}

/* SYNTAX: RAWLOG SAVE <file> */
static void cmd_rawlog_save(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || server->rawlog == NULL)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
	rawlog_save(server->rawlog, data);
}

/* SYNTAX: RAWLOG OPEN <file> */
static void cmd_rawlog_open(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || server->rawlog == NULL)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
	rawlog_open(server->rawlog, data);
}

/* SYNTAX: RAWLOG CLOSE */
static void cmd_rawlog_close(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || server->rawlog == NULL)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	rawlog_close(server->rawlog);
}

void rawlog_init(void)
{
	signal_rawlog = signal_get_uniq_id("rawlog");

	settings_add_int("history", "rawlog_lines", 200);
	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	command_bind("rawlog", NULL, (SIGNAL_FUNC) cmd_rawlog);
	command_bind("rawlog save", NULL, (SIGNAL_FUNC) cmd_rawlog_save);
	command_bind("rawlog open", NULL, (SIGNAL_FUNC) cmd_rawlog_open);
	command_bind("rawlog close", NULL, (SIGNAL_FUNC) cmd_rawlog_close);
}

void rawlog_deinit(void)
{
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	command_unbind("rawlog", (SIGNAL_FUNC) cmd_rawlog);
	command_unbind("rawlog save", (SIGNAL_FUNC) cmd_rawlog_save);
	command_unbind("rawlog open", (SIGNAL_FUNC) cmd_rawlog_open);
	command_unbind("rawlog close", (SIGNAL_FUNC) cmd_rawlog_close);
}
