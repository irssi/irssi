/*
 autoignore.c : irssi

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
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"

#include "irc-servers.h"
#include "ignore.h"

#include "autoignore.h"

void autoignore_update(IGNORE_REC *rec, int level)
{
	rec->level |= level;
	rec->time = settings_get_int("autoignore_time");

	ignore_update_rec(rec);
}

void autoignore_add(IRC_SERVER_REC *server, char *mask, int level) 
{
	IGNORE_REC *rec;

	rec = g_new0(IGNORE_REC, 1);
	
	rec->mask = mask;
	rec->servertag = g_strdup(server->tag);
	rec->level = level;
	rec->time = settings_get_int("autoignore_time");
	rec->autoignore = 1;
	
	ignore_add_rec(rec);
}

static void sig_flood(IRC_SERVER_REC *server, const char *nick, const char *host, gpointer levelp)
{
	int level, check_level;
	GString *mask;
	IGNORE_REC *rec;

	g_return_if_fail(IS_IRC_SERVER(server));

	level = GPOINTER_TO_INT(levelp);
	check_level = level2bits(settings_get_str("autoignore_level"));

	mask = g_string_new(nick);
	mask = g_string_append_c(mask, '!');
	mask = g_string_append(mask, host);
	if (level & check_level) {
		rec = ignore_find(server->tag, mask->str, NULL);
		if (rec == NULL)
			autoignore_add(server, mask->str, level);
		else
			autoignore_update(rec, level);
	}
        g_string_free(mask, TRUE);
}

void autoignore_init(void)
{
	settings_add_int("flood", "autoignore_time", 300);
	settings_add_str("flood", "autoignore_level", "");

  	signal_add("flood", (SIGNAL_FUNC) sig_flood);
}

void autoignore_deinit(void)
{
	signal_remove("flood", (SIGNAL_FUNC) sig_flood);
}
