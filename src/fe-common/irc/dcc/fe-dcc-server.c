/*
 fe-dcc-server.c : irssi

    Copyright (C) 2003 Mark Trumbull

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
#include "network.h"
#include "levels.h"

#include "dcc-server.h"

#include "module-formats.h"
#include "printtext.h"
#include "themes.h"

static void dcc_server_started(SERVER_DCC_REC *dcc)
{
	if (!IS_DCC_SERVER(dcc)) {
		return;
	}

	printformat(dcc->server, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_SERVER_STARTED, dcc->port);
}

static void dcc_closed(SERVER_DCC_REC *dcc)
{
	/* We don't want to print a msg if its just starting a chat/get */
	/* and getting rid of the leftover SERVER_DCC_REC */
	if (!IS_DCC_SERVER(dcc) || dcc->connection_established) {
		return;
	}

	printformat(dcc->server, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_SERVER_CLOSED, dcc->port);
}

static void sig_dcc_list_print(SERVER_DCC_REC *dcc)
{
	/* We don't want to print a msg if its just starting a chat/get */
	/* and getting rid of the leftover SERVER_DCC_REC */
	if (!IS_DCC_SERVER(dcc) || dcc->connection_established) {
		return;
	}

	/* SERVER: Port(59) - Send(on) - Chat(on) - Fserve(on) */
	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_LINE_SERVER,
		    "SERVER", dcc->port, dcc->accept_send ? "on" : "off",
		    dcc->accept_chat ? "on" : "off",
		    dcc->accept_fserve ? "on" : "off");
}

void fe_dcc_server_init(void)
{
	signal_add("dcc server started", (SIGNAL_FUNC) dcc_server_started);
	signal_add("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_add("dcc list print", (SIGNAL_FUNC) sig_dcc_list_print);
}

void fe_dcc_server_deinit(void)
{
	signal_remove("dcc server started", (SIGNAL_FUNC) dcc_server_started);
	signal_remove("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_remove("dcc list print", (SIGNAL_FUNC) sig_dcc_list_print);
}

