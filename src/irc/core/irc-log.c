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

static void sig_log(SERVER_REC *server, const char *channel, gpointer level, const char *str)
{
	int loglevel;

	g_return_if_fail(str != NULL);

	loglevel = GPOINTER_TO_INT(level);
	if (loglevel == MSGLEVEL_NEVER || logs == NULL) return;

	/* Check if line should be saved in logs */
	log_write(channel, loglevel, str);
}


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
	if (log != NULL) {
		/* awaylog already created */
		if (log->handle == -1) {
			/* ..but not open, open it. */
			log_start_logging(log);
		}
		return;
	}

	log = log_create_rec(fname, level, NULL);
	if (log != NULL) {
		log->temp = TRUE;
		log_update(log);
		log_start_logging(log);
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

	signal_add("print text stripped", (SIGNAL_FUNC) sig_log);
	signal_add("event 306", (SIGNAL_FUNC) event_away);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
}

void irc_log_deinit(void)
{
	signal_remove("print text stripped", (SIGNAL_FUNC) sig_log);
	signal_remove("event 306", (SIGNAL_FUNC) event_away);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
}
