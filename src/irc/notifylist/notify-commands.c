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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "settings.h"

#include "notifylist.h"

/* SYNTAX: NOTIFY [-away] <mask> [<ircnets>] */
static void cmd_notify(gchar *data)
{
	GHashTable *optlist;
	char *mask, *ircnets;
	void *free_arg;
	int away_check;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS | PARAM_FLAG_GETREST,
			    "notify", &optlist, &mask, &ircnets))
		return;
	if (*mask == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	away_check = g_hash_table_lookup(optlist, "away") != NULL;
	notifylist_remove(mask);
	notifylist_add(mask, ircnets, away_check);

	cmd_params_free(free_arg);
}

/* SYNTAX: UNNOTIFY <mask> */
static void cmd_unnotify(const char *data)
{
	char *mask;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1, &mask))
		return;
	if (*mask == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	notifylist_remove(mask);

	cmd_params_free(free_arg);
}

void notifylist_commands_init(void)
{
	command_bind("notify", NULL, (SIGNAL_FUNC) cmd_notify);
	command_bind("unnotify", NULL, (SIGNAL_FUNC) cmd_unnotify);

	command_set_options("notify", "away");
}

void notifylist_commands_deinit(void)
{
	command_unbind("notify", (SIGNAL_FUNC) cmd_notify);
	command_unbind("unnotify", (SIGNAL_FUNC) cmd_unnotify);
}
