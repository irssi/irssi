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

#include "levels.h"
#include "irc-server.h"
#include "server-reconnect.h"
#include "server-setup.h"

#include "windows.h"

static void print_servers(void)
{
	GSList *tmp;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CRAP, IRCTXT_SERVER_LIST,
			    rec->tag, rec->connrec->address, rec->connrec->port,
			    rec->connrec->ircnet == NULL ? "" : rec->connrec->ircnet, rec->connrec->nick);
	}
}

static void print_lookup_servers(void)
{
	GSList *tmp;
	for (tmp = lookup_servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CRAP, IRCTXT_SERVER_LOOKUP_LIST,
			    rec->tag, rec->connrec->address, rec->connrec->port,
			    rec->connrec->ircnet == NULL ? "" : rec->connrec->ircnet, rec->connrec->nick);
	}
}

static void print_reconnects(void)
{
	GSList *tmp;
	char *tag, *next_connect;
	int left;

	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		RECONNECT_REC *rec = tmp->data;
		IRC_SERVER_CONNECT_REC *conn = rec->conn;

		tag = g_strdup_printf("RECON-%d", rec->tag);
		left = rec->next_connect-time(NULL);
		next_connect = g_strdup_printf("%02d:%02d", left/60, left%60);
		printformat(NULL, NULL, MSGLEVEL_CRAP, IRCTXT_SERVER_RECONNECT_LIST,
			    tag, conn->address, conn->port,
			    conn->ircnet == NULL ? "" : conn->ircnet,
			    conn->nick, next_connect);
		g_free(next_connect);
		g_free(tag);
	}
}

static void cmd_server_add(const char *data)
{
        GHashTable *optlist;
	SETUP_SERVER_REC *rec;
	char *addr, *portstr, *password, *value;
	void *free_arg;
	int port;

	if (!cmd_get_params(data, &free_arg, 3 | PARAM_FLAG_OPTIONS,
			    "server add", &optlist, &addr, &portstr, &password))
		return;

	if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	port = *portstr == '\0' ? 6667 : atoi(portstr);

	rec = server_setup_find(addr, port);
	if (rec == NULL) {
		rec = g_new0(SETUP_SERVER_REC, 1);
		rec->address = g_strdup(addr);
		rec->port = port;
	} else {
		value = g_hash_table_lookup(optlist, "port");
		if (value != NULL && *value != '\0') rec->port = atoi(value);

		if (g_hash_table_lookup(optlist, "ircnet")) g_free_and_null(rec->ircnet);
		if (*password != '\0') g_free_and_null(rec->password);
		if (g_hash_table_lookup(optlist, "host")) {
			g_free_and_null(rec->own_host);
			rec->own_ip = NULL;
		}
	}

	if (g_hash_table_lookup(optlist, "auto")) rec->autoconnect = TRUE;
	if (g_hash_table_lookup(optlist, "noauto")) rec->autoconnect = FALSE;

	if (*password != '\0' && strcmp(password, "-") != 0) rec->password = g_strdup(password);
	value = g_hash_table_lookup(optlist, "ircnet");
	if (value != NULL && *value != '\0') rec->ircnet = g_strdup(value);
	value = g_hash_table_lookup(optlist, "host");
	if (value != NULL && *value != '\0') {
		rec->own_host = g_strdup(value);
		rec->own_ip = NULL;
	}
	value = g_hash_table_lookup(optlist, "cmdspeed");
	if (value != NULL && *value != '\0') rec->cmd_queue_speed = atoi(value);
	value = g_hash_table_lookup(optlist, "cmdmax");
	if (value != NULL && *value != '\0') rec->max_cmds_at_once = atoi(value);

	server_setup_add(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SETUPSERVER_ADDED, addr, port);

	cmd_params_free(free_arg);
}

static void cmd_server_remove(const char *data)
{
	SETUP_SERVER_REC *rec;
	char *addr, *portstr;
	void *free_arg;
	int port;

	if (!cmd_get_params(data, &free_arg, 2, &addr, &portstr))
		return;
	if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	port = *portstr == '\0' ? 6667 : atoi(portstr);

	rec = server_setup_find(addr, port);
	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SETUPSERVER_NOT_FOUND, addr, port);
	else {
		server_setup_remove(rec);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SETUPSERVER_REMOVED, addr, port);
	}

	cmd_params_free(free_arg);
}

static void cmd_server_list(const char *data)
{
	GString *str;
	GSList *tmp;

	str = g_string_new(NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_SETUPSERVER_HEADER);
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SETUP_SERVER_REC *rec = tmp->data;

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
			    rec->ircnet == NULL ? "" : rec->ircnet,
			    str->str);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_SETUPSERVER_FOOTER);
	g_string_free(str, TRUE);
}

static void cmd_server(const char *data, IRC_SERVER_REC *server, void *item)
{
	GHashTable *optlist;
	char *addr;
	void *free_arg;

	if (*data == '\0') {
		print_servers();
		print_lookup_servers();
		print_reconnects();

		signal_stop();
		return;
	}

	if (g_strncasecmp(data, "add ", 4) == 0 ||
	    g_strncasecmp(data, "remove ", 7) == 0 ||
	    g_strcasecmp(data, "list") == 0 ||
	    g_strncasecmp(data, "list ", 5) == 0) {
		command_runsub("server", data, server, item);
		signal_stop();
		return;
	}

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "connect", &optlist, &addr))
		return;

	if (*addr == '\0' || strcmp(addr, "+") == 0)
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	if (*addr == '+') window_create(NULL, FALSE);

	cmd_params_free(free_arg);
}

void fe_irc_server_init(void)
{
	command_bind("server", NULL, (SIGNAL_FUNC) cmd_server);
	command_bind("server add", NULL, (SIGNAL_FUNC) cmd_server_add);
	command_bind("server remove", NULL, (SIGNAL_FUNC) cmd_server_remove);
	command_bind("server list", NULL, (SIGNAL_FUNC) cmd_server_list);

	command_set_options("server add", "auto noauto -ircnet -host -cmdspeed -cmdmax -port");
}

void fe_irc_server_deinit(void)
{
	command_unbind("server", (SIGNAL_FUNC) cmd_server);
	command_unbind("server add", (SIGNAL_FUNC) cmd_server_add);
	command_unbind("server remove", (SIGNAL_FUNC) cmd_server_remove);
	command_unbind("server list", (SIGNAL_FUNC) cmd_server_list);
}
