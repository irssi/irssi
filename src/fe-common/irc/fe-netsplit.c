/*
 fe-netsplit.c : irssi

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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"

#include "levels.h"
#include "netsplit.h"

static void sig_netsplit_servers(IRC_SERVER_REC *server, NETSPLIT_SERVER_REC *rec)
{
    printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_NETSPLIT, rec->server, rec->destserver, server->tag);
}

static void split_print(const char *nick, NETSPLIT_REC *rec)
{
	NETSPLIT_CHAN_REC *chan;

	chan = rec->channels->data;
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_LINE,
		    rec->nick, chan == NULL ? "" : chan->name,
		    rec->server->server, rec->server->destserver);
}

static void cmd_netsplit(const char *data, IRC_SERVER_REC *server)
{
	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (server->split_servers == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_NO_NETSPLITS);
		return;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_HEADER);
        g_hash_table_foreach(server->splits, (GHFunc) split_print, NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NETSPLITS_FOOTER);
}

void fe_netsplit_init(void)
{
	signal_add("netsplit new server", (SIGNAL_FUNC) sig_netsplit_servers);
	command_bind("netsplit", NULL, (SIGNAL_FUNC) cmd_netsplit);
}

void fe_netsplit_deinit(void)
{
	signal_remove("netsplit new server", (SIGNAL_FUNC) sig_netsplit_servers);
	command_unbind("netsplit", (SIGNAL_FUNC) cmd_netsplit);
}
