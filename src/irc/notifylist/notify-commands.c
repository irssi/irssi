/*
 notify-commands.c : irssi

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
#include "commands.h"
#include "misc.h"
#include "settings.h"

#include "notifylist.h"

#define DEFAULT_NOTIFY_IDLE_TIME 60

static void cmd_notify(gchar *data)
{
	char *params, *mask, *ircnets, *args, *idletime;
	int away_check, idle_check_time;

	g_return_if_fail(data != NULL);

	args = "@idle";
	params = cmd_get_params(data, 4 | PARAM_FLAG_MULTIARGS | PARAM_FLAG_GETREST, &args, &idletime, &mask, &ircnets);
	if (*mask == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (stristr(args, "-idle") == NULL)
		idle_check_time = 0;
	else {
		idle_check_time = is_numeric(idletime, 0) ? (atoi(idletime)*60) :
			(settings_get_int("notify_idle_time")*60);
	}

	away_check = stristr(args, "-away") != NULL;
	notifylist_remove(mask);
	notifylist_add(mask, ircnets, away_check, idle_check_time);

	g_free(params);
}

static void cmd_unnotify(const char *data)
{
	char *params, *mask;

	g_return_if_fail(data != NULL);

	params = cmd_get_params(data, 1, &mask);
	if (*mask == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	notifylist_remove(mask);

	g_free(params);
}

void notifylist_commands_init(void)
{
	settings_add_int("misc", "notify_idle_time", DEFAULT_NOTIFY_IDLE_TIME);
	command_bind("notify", NULL, (SIGNAL_FUNC) cmd_notify);
	command_bind("unnotify", NULL, (SIGNAL_FUNC) cmd_unnotify);
}

void notifylist_commands_deinit(void)
{
	command_unbind("notify", (SIGNAL_FUNC) cmd_notify);
	command_unbind("unnotify", (SIGNAL_FUNC) cmd_unnotify);
}
