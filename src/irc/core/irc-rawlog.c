/*
 irc-rawlog.c : irssi

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
#include "rawlog.h"
#include "modules.h"
#include "signals.h"
#include "misc.h"

#include "commands.h"
#include "server.h"

#include "settings.h"

static void cmd_rawlog(const char *data, SERVER_REC *server, void *item)
{
	command_runsub("rawlog", data, server, item);
}

static void cmd_rawlog_save(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
	rawlog_save(server->rawlog, data);
}

static void cmd_rawlog_open(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
	rawlog_open(server->rawlog, data);
}

static void cmd_rawlog_close(const char *data, SERVER_REC *server)
{
	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected) cmd_return_error(CMDERR_NOT_CONNECTED);

	rawlog_close(server->rawlog);
}

void irc_rawlog_init(void)
{
	command_bind("rawlog", NULL, (SIGNAL_FUNC) cmd_rawlog);
	command_bind("rawlog save", NULL, (SIGNAL_FUNC) cmd_rawlog_save);
	command_bind("rawlog open", NULL, (SIGNAL_FUNC) cmd_rawlog_open);
	command_bind("rawlog close", NULL, (SIGNAL_FUNC) cmd_rawlog_close);
}

void irc_rawlog_deinit(void)
{
	command_unbind("rawlog", (SIGNAL_FUNC) cmd_rawlog);
	command_unbind("rawlog save", (SIGNAL_FUNC) cmd_rawlog_save);
	command_unbind("rawlog open", (SIGNAL_FUNC) cmd_rawlog_open);
	command_unbind("rawlog close", (SIGNAL_FUNC) cmd_rawlog_close);
}
