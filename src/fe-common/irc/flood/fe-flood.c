/*
 fe-flood.c : irssi

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
#include "signals.h"
#include "levels.h"

#include "irc-server.h"
#include "irc/flood/autoignore.h"

#include "themes.h"

static void event_autoignore_new(IRC_SERVER_REC *server, AUTOIGNORE_REC *ignore)
{
	g_return_if_fail(ignore != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_AUTOIGNORE,
		    ignore->nick, (ignore->timeleft+59)/60);
}

static void event_autoignore_remove(IRC_SERVER_REC *server, AUTOIGNORE_REC *ignore)
{
	g_return_if_fail(ignore != NULL);

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_AUTOUNIGNORE, ignore->nick);
}

void fe_irc_flood_init(void)
{
	signal_add("autoignore new", (SIGNAL_FUNC) event_autoignore_new);
	signal_add("autoignore remove", (SIGNAL_FUNC) event_autoignore_remove);

        theme_register(fecommon_irc_flood_formats);
}

void fe_irc_flood_deinit(void)
{
	theme_unregister();

	signal_remove("autoignore new", (SIGNAL_FUNC) event_autoignore_new);
	signal_remove("autoignore remove", (SIGNAL_FUNC) event_autoignore_remove);
}
