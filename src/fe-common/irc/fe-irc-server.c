/*
 fe-irc-server.c : irssi

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
#include "commands.h"
#include "misc.h"

#include "servers-setup.h"

#include "levels.h"
#include "irc-servers.h"
#include "servers-reconnect.h"
#include "irc-servers-setup.h"

#include "fe-windows.h"
#include "printtext.h"

static void sig_server_add_create(IRC_SERVER_SETUP_REC **rec,
				  GHashTable *optlist)
{
	char *ircnet;

	ircnet = g_hash_table_lookup(optlist, "ircnet");
	if (ircnet == NULL)
		return;

	*rec = g_new0(IRC_SERVER_SETUP_REC, 1);
	(*rec)->chat_type = chat_protocol_lookup("IRC");
	signal_stop();
}

static void sig_server_add_fill(IRC_SERVER_SETUP_REC *rec,
				GHashTable *optlist)
{
	char *value;

	value = g_hash_table_lookup(optlist, "ircnet");
	if (value != NULL) {
		g_free_and_null(rec->chatnet);
		if (*value != '\0') rec->chatnet = g_strdup(value);
	}

	value = g_hash_table_lookup(optlist, "cmdspeed");
	if (value != NULL && *value != '\0') rec->cmd_queue_speed = atoi(value);
	value = g_hash_table_lookup(optlist, "cmdmax");
	if (value != NULL && *value != '\0') rec->max_cmds_at_once = atoi(value);
}

/* SYNTAX: SERVER LIST */
static void cmd_server_list(const char *data)
{
	GString *str;
	GSList *tmp;

	str = g_string_new(NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_SETUPSERVER_HEADER);
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_SETUP_REC *rec = tmp->data;

		if (!IS_IRC_SERVER_SETUP(rec))
                        continue;

		g_string_truncate(str, 0);
		if (rec->password != NULL)
			g_string_append(str, "(pass), ");
		if (rec->autoconnect)
			g_string_append(str, "autoconnect, ");
		if (rec->max_cmds_at_once > 0)
			g_string_sprintfa(str, "cmdmax: %d, ", rec->max_cmds_at_once);
		if (rec->cmd_queue_speed > 0)
			g_string_sprintfa(str, "cmdspeed: %d, ", rec->cmd_queue_speed);
		if (rec->own_host != NULL)
			g_string_sprintfa(str, "host: %s, ", rec->own_host);

		if (str->len > 1) g_string_truncate(str, str->len-2);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_SETUPSERVER_LINE,
			    rec->address, rec->port,
			    rec->chatnet == NULL ? "" : rec->chatnet,
			    str->str);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_SETUPSERVER_FOOTER);
	g_string_free(str, TRUE);
}

void fe_irc_server_init(void)
{
	signal_add("server add create", (SIGNAL_FUNC) sig_server_add_create);
	signal_add("server add fill", (SIGNAL_FUNC) sig_server_add_fill);
	command_bind("server list", NULL, (SIGNAL_FUNC) cmd_server_list);

	command_set_options("server add", "-ircnet");
}

void fe_irc_server_deinit(void)
{
	signal_remove("server add create", (SIGNAL_FUNC) sig_server_add_create);
	signal_remove("server add fill", (SIGNAL_FUNC) sig_server_add_fill);
	command_unbind("server list", (SIGNAL_FUNC) cmd_server_list);
}
