/*
 irc-log.c : irssi

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
#include "signals.h"
#include "levels.h"
#include "log.h"
#include "settings.h"

#include "irc-server.h"

static void event_away(const char *data, IRC_SERVER_REC *server)
{
	const char *fname, *levelstr;
	LOG_REC *log;
	int level;

	fname = settings_get_str("awaylog_file");
	levelstr = settings_get_str("awaylog_level");
	if (*fname == '\0' || *levelstr == '\0') return;

	level = level2bits(levelstr);
	if (level == 0) return;

	log = log_find(fname);
	if (log == NULL) {
		log = log_create_rec(fname, level, NULL);
		log->temp = TRUE;
		log_update(log);
	}

	if (!log_start_logging(log)) {
		/* creating log file failed? close it. */
		log_close(log);
	}
}

static void event_unaway(const char *data, IRC_SERVER_REC *server)
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

	log_close(log);
}

void irc_log_init(void)
{
	settings_add_str("log", "awaylog_file", "~/.irssi/away.log");
	settings_add_str("log", "awaylog_level", "msgs hilight");

	signal_add("event 306", (SIGNAL_FUNC) event_away);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
}

void irc_log_deinit(void)
{
	signal_remove("event 306", (SIGNAL_FUNC) event_away);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
}
