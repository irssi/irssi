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

static void server_add(const char *data)
{
	SETUP_SERVER_REC *rec;
	char *params, *args, *ircnet, *host, *cmdspeed, *cmdmax, *portarg;
	char *addr, *portstr, *password;
	int port;

	args = "ircnet host cmdspeed cmdmax port";
	params = cmd_get_params(data, 9 | PARAM_FLAG_MULTIARGS,
				&args, &ircnet, &host, &cmdspeed, &cmdmax,
				&portarg, &addr, &portstr, &password);
	if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	port = *portstr == '\0' ? 6667 : atoi(portstr);

	rec = server_setup_find(addr, port);
	if (rec == NULL) {
		rec = g_new0(SETUP_SERVER_REC, 1);
		rec->address = g_strdup(addr);
		rec->port = port;
	} else {
		if (*portarg != '\0') rec->port = atoi(portarg);
		if (stristr(args, "-ircnet")) g_free_and_null(rec->ircnet);
		if (*password != '\0') g_free_and_null(rec->password);
		if (stristr(args, "-host")) {
			g_free_and_null(rec->own_host);
			rec->own_ip = NULL;
		}
	}

	if (stristr(args, "-auto")) rec->autoconnect = TRUE;
	if (stristr(args, "-noauto")) rec->autoconnect = FALSE;
	if (*ircnet != '\0') rec->ircnet = g_strdup(ircnet);
	if (*password != '\0' && strcmp(password, "-") != 0) rec->password = g_strdup(password);
	if (*host != '\0') {
		rec->own_host = g_strdup(host);
		rec->own_ip = NULL;
	}
	if (*cmdspeed != '\0') rec->cmd_queue_speed = atoi(cmdspeed);
	if (*cmdmax != '\0') rec->max_cmds_at_once = atoi(cmdmax);

	server_setup_add(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SETUPSERVER_ADDED, addr, port);

	g_free(params);
}

static void server_remove(const char *data)
{
	SETUP_SERVER_REC *rec;
	char *params, *args, *addr, *portstr;
	int port;

	params = cmd_get_params(data, 3 | PARAM_FLAG_OPTARGS, &args, &addr, &portstr);
	if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
	port = *portstr == '\0' ? 6667 : atoi(portstr);

	rec = server_setup_find(addr, port);
	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SETUPSERVER_NOT_FOUND, addr, port);
	else {
		server_setup_remove(rec);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_SETUPSERVER_REMOVED, addr, port);
	}

        g_free(params);
}

static void server_list(const char *data)
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

static void cmd_server(const char *data)
{
	char *params, *args, *ircnetarg, *hostarg, *addr;

	if (*data == '\0') {
		print_servers();
		print_lookup_servers();
		print_reconnects();

		signal_stop();
		return;
	}

	args = "ircnet host"; /* should be same as in connect_server() in src/irc/core/irc-commands.c */
	params = cmd_get_params(data, 4 | PARAM_FLAG_MULTIARGS,
				&args, &ircnetarg, &hostarg, &addr);

	if (stristr(args, "-list") != NULL) {
		server_list(data);
		signal_stop();
	} else if (stristr(args, "-add") != NULL) {
		if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
                server_add(data);
		signal_stop();
	} else if (stristr(args, "-remove") != NULL) {
		if (*addr == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
		server_remove(data);
		signal_stop();
	} else {
		if (*addr == '\0' || strcmp(addr, "+") == 0)
			cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);
		if (*addr == '+') window_create(NULL, FALSE);
	}

	g_free(params);
}

void fe_irc_server_init(void)
{
	command_bind("server", NULL, (SIGNAL_FUNC) cmd_server);
}

void fe_irc_server_deinit(void)
{
	command_unbind("server", (SIGNAL_FUNC) cmd_server);
}
