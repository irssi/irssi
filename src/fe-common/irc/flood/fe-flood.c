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

#include "irc-servers.h"
#include "ignore.h"
#include "irc/flood/autoignore.h"

#include "themes.h"
#include "printtext.h"

static void event_autoignore_new(IGNORE_REC *rec)
{
	g_return_if_fail(rec != NULL);
 
	printformat(server_find_tag(rec->servertag), NULL, MSGLEVEL_CLIENTNOTICE, 
								IRCTXT_AUTOIGNORE, rec->mask, rec->time);
}                                                                              

static void event_autoignore_destroyed(IGNORE_REC *rec)
{
	g_return_if_fail(rec != NULL);
 
	printformat(server_find_tag(rec->servertag), NULL, MSGLEVEL_CLIENTNOTICE,
				IRCTXT_AUTOUNIGNORE, rec->mask, rec->time);
}                                                                                                                                          
void fe_irc_flood_init(void)
{
    signal_add("autoignore new", (SIGNAL_FUNC) event_autoignore_new);
    signal_add("autoignore destroyed", (SIGNAL_FUNC) event_autoignore_destroyed);

	theme_register(fecommon_irc_flood_formats);
}

void fe_irc_flood_deinit(void)
{
	signal_remove("autoignore new", (SIGNAL_FUNC) event_autoignore_new);
	signal_remove("autoignore destroyed", (SIGNAL_FUNC) event_autoignore_destroyed);
	theme_unregister();
}
