/*
 chat-commands.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "special-vars.h"

#include "servers.h"
#include "chat-protocols.h"
#include "window-item-def.h"

/* SYNTAX: JOIN [-invite] [-<server tag>] <channels> [<keys>] */
static void cmd_join(const char *data, SERVER_REC *server)
{
	GHashTable *optlist;
	char *channels;
	void *free_arg;

	g_return_if_fail(data != NULL);
	if (!IS_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "join", &optlist, &channels))
		return;

	if (g_hash_table_lookup(optlist, "invite"))
		channels = server->last_invite;
	else {
		if (*channels == '\0')
			cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

		/* -<server tag> */
		server = cmd_options_get_server("join", optlist, server);
	}

	if (server != NULL && channels != NULL)
		server->channels_join(server, channels, FALSE);
	cmd_params_free(free_arg);
}

/* SYNTAX: MSG [-<server tag>] <targets> <message> */
static void cmd_msg(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	GHashTable *optlist;
	char *target, *msg;
	void *free_arg;
	int free_ret;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "msg", &optlist, &target, &msg))
		return;
	if (*target == '\0' || *msg == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	server = cmd_options_get_server("msg", optlist, SERVER(server));
	if (server == NULL || !server->connected)
		cmd_param_error(CMDERR_NOT_CONNECTED);

	free_ret = FALSE;
	if (strcmp(target, ",") == 0 || strcmp(target, ".") == 0) {
		target = parse_special(&target, server, item,
				       NULL, &free_ret, NULL);
	} else if (strcmp(target, "*") == 0 && item != NULL)
		target = item->name;

	if (target != NULL)
		server->send_message(server, target, msg);

	if (free_ret && target != NULL) g_free(target);
	cmd_params_free(free_arg);
}

void chat_commands_init(void)
{
	command_bind("join", NULL, (SIGNAL_FUNC) cmd_join);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);
	command_set_options("join", "invite");
}

void chat_commands_deinit(void)
{
	command_unbind("join", (SIGNAL_FUNC) cmd_join);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
}
