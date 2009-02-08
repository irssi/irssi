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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"

#include "servers-setup.h"

#include "levels.h"
#include "irc-chatnets.h"
#include "irc-servers.h"
#include "irc-channels.h"
#include "servers-reconnect.h"
#include "irc-servers-setup.h"

#include "fe-windows.h"
#include "printtext.h"

const char *get_visible_target(IRC_SERVER_REC *server, const char *target)
{
	IRC_CHANNEL_REC *channel;

	if (*target == '!') {
		/* visible_name of !channels is different - don't bother
		   checking other types for now, they'll just slow up */
		channel = irc_channel_find(server, target);
		if (channel != NULL)
			return channel->visible_name;
	}

	return target;
}
/* SYNTAX: SERVER ADD [-4 | -6] [-ssl] [-ssl_cert <cert>] [-ssl_pkey <pkey>]
                      [-ssl_verify] [-ssl_cafile <cafile>] [-ssl_capath <capath>]
                      [-auto | -noauto] [-network <network>] [-host <hostname>]
                      [-cmdspeed <ms>] [-cmdmax <count>] [-port <port>]
                      <address> [<port> [<password>]] */
/* NOTE: -network replaces the old -ircnet flag. */
static void sig_server_add_fill(IRC_SERVER_SETUP_REC *rec,
				GHashTable *optlist)
{
        IRC_CHATNET_REC *ircnet;
	char *value;

	value = g_hash_table_lookup(optlist, "network");
	/* For backwards compatibility, also allow the old name 'ircnet'. 
	   But of course only if -network was not given. */
	if (!value)
		value = g_hash_table_lookup(optlist, "ircnet");

	if (value != NULL) {
		g_free_and_null(rec->chatnet);
		if (*value != '\0') {
			ircnet = ircnet_find(value);
			rec->chatnet = ircnet != NULL ?
				g_strdup(ircnet->name) : g_strdup(value);
		}
	}

	value = g_hash_table_lookup(optlist, "cmdspeed");
	if (value != NULL && *value != '\0') rec->cmd_queue_speed = atoi(value);
	value = g_hash_table_lookup(optlist, "cmdmax");
	if (value != NULL && *value != '\0') rec->max_cmds_at_once = atoi(value);
	value = g_hash_table_lookup(optlist, "querychans");
	if (value != NULL && *value != '\0') rec->max_query_chans = atoi(value);
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
		if (rec->no_proxy)
			g_string_append(str, "noproxy, ");
		if (rec->use_ssl) {
			g_string_append(str, "ssl, ");
			if (rec->ssl_cert) {
				g_string_append_printf(str, "ssl_cert: %s, ", rec->ssl_cert);
				if (rec->ssl_pkey)
					g_string_append_printf(str, "ssl_pkey: %s, ", rec->ssl_pkey);
			}
			if (rec->ssl_verify)
				g_string_append(str, "ssl_verify, ");
			if (rec->ssl_cafile)
				g_string_append_printf(str, "ssl_cafile: %s, ", rec->ssl_cafile);
			if (rec->ssl_capath)
				g_string_append_printf(str, "ssl_capath: %s, ", rec->ssl_capath);
			
		}
		if (rec->max_cmds_at_once > 0)
			g_string_append_printf(str, "cmdmax: %d, ", rec->max_cmds_at_once);
		if (rec->cmd_queue_speed > 0)
			g_string_append_printf(str, "cmdspeed: %d, ", rec->cmd_queue_speed);
		if (rec->max_query_chans > 0)
			g_string_append_printf(str, "querychans: %d, ", rec->max_query_chans);
		if (rec->own_host != NULL)
			g_string_append_printf(str, "host: %s, ", rec->own_host);

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
	signal_add("server add fill", (SIGNAL_FUNC) sig_server_add_fill);
	command_bind("server list", NULL, (SIGNAL_FUNC) cmd_server_list);

	command_set_options("server add", "-ircnet -network -cmdspeed -cmdmax -querychans");
}

void fe_irc_server_deinit(void)
{
	signal_remove("server add fill", (SIGNAL_FUNC) sig_server_add_fill);
	command_unbind("server list", (SIGNAL_FUNC) cmd_server_list);
}
