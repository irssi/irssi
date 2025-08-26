/*
 log-away.c : Awaylog handling

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

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/log.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/write-buffer.h>

static LOG_REC *awaylog;
static int away_filepos;
static int away_msgs;

static void sig_log_written(LOG_REC *log)
{
	if (log != awaylog) return;

        away_msgs++;
}

static void awaylog_open(void)
{
	const char *fname;
	LOG_REC *log;
	int level;

	fname = settings_get_str("awaylog_file");
	level = settings_get_level("awaylog_level");
	if (*fname == '\0' || level == 0) return;

	log = log_find(fname);
	if (log != NULL && log->handle != -1)
		return; /* already open */

	if (log == NULL) {
		log = log_create_rec(fname, level);
		log->temp = TRUE;
		log_update(log);
	}

	if (!log_start_logging(log)) {
		/* creating log file failed? close it. */
		log_close(log);
		return;
	}

	/* Flush the dirty buffers to disk before acquiring the file position */
	write_buffer_flush();

	awaylog = log;
	away_filepos = lseek(log->handle, 0, SEEK_CUR);
	away_msgs = 0;
}

static void awaylog_close(void)
{
	const char *fname;
	LOG_REC *log;

	fname = settings_get_str("awaylog_file");
	if (*fname == '\0') return;

	log = log_find(fname);
	if (log == NULL || log->handle == -1) {
		/* awaylog not open */
		return;
	}

	if (awaylog == log) awaylog = NULL;

	/* Flush the dirty buffers to disk before showing the away log */
	write_buffer_flush();

	signal_emit("awaylog show", 3, log, GINT_TO_POINTER(away_msgs),
		    GINT_TO_POINTER(away_filepos));
	log_close(log);
}

static void sig_away_changed(SERVER_REC *server)
{
	if (server->usermode_away)
		awaylog_open();
	else
                awaylog_close();
}

void log_away_init(void)
{
	char *awaylog_file;

	awaylog = NULL;
	away_filepos = 0;
	away_msgs = 0;

	awaylog_file = g_strconcat(get_irssi_dir(), "/away.log", NULL);
	settings_add_str("log", "awaylog_file", awaylog_file);
	g_free(awaylog_file);
	settings_add_level("log", "awaylog_level", "msgs hilight");

	signal_add("log written", (SIGNAL_FUNC) sig_log_written);
	signal_add("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}

void log_away_deinit(void)
{
	signal_remove("log written", (SIGNAL_FUNC) sig_log_written);
	signal_remove("away mode changed", (SIGNAL_FUNC) sig_away_changed);
}
