/*
 autoignore.c : irssi

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
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"

#include "irc-servers.h"
#include "ignore.h"

void autoignore_update(IGNORE_REC *rec, int level)
{
	rec->level |= level;
	rec->unignore_time = time(NULL) +
		settings_get_time("autoignore_time")/1000;

	ignore_update_rec(rec);
}

void autoignore_add(IRC_SERVER_REC *server, char *mask, int level) 
{
	IGNORE_REC *rec;

	rec = g_new0(IGNORE_REC, 1);

	rec->mask = g_strdup(mask);
	rec->servertag = g_strdup(server->tag);
	rec->level = level;
	rec->unignore_time = time(NULL) +
		settings_get_time("autoignore_time")/1000;

	ignore_add_rec(rec);
}

static void sig_flood(IRC_SERVER_REC *server, const char *nick, const char *host, gpointer levelp)
{
	IGNORE_REC *rec;
	char *mask;
	int level, check_level;

	g_return_if_fail(IS_IRC_SERVER(server));

	level = GPOINTER_TO_INT(levelp);
	check_level = settings_get_level("autoignore_level");

        mask = g_strdup_printf("%s!%s", nick, host);
	if (level & check_level) {
		rec = ignore_find(server->tag, mask, NULL);
		if (rec == NULL)
			autoignore_add(server, mask, level);
		else
			autoignore_update(rec, level);
	}
        g_free(mask);
}

void autoignore_init(void)
{
	settings_add_time("flood", "autoignore_time", "5min");
	settings_add_level("flood", "autoignore_level", "");

  	signal_add("flood", (SIGNAL_FUNC) sig_flood);
}

void autoignore_deinit(void)
{
	signal_remove("flood", (SIGNAL_FUNC) sig_flood);
}
