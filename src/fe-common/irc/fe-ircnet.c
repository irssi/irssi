/*
 fe-ircnet.c : irssi

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
#include "misc.h"

#include "irc-server.h"
#include "ircnet-setup.h"

static void cmd_ircnet(const char *data, IRC_SERVER_REC *server, WI_ITEM_REC *item)
{
        command_runsub("ircnet", data, server, item);
}

static void cmd_ircnet_list(void)
{
	GString *str;
	GSList *tmp;

	str = g_string_new(NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_IRCNET_HEADER);
	for (tmp = ircnets; tmp != NULL; tmp = tmp->next) {
		IRCNET_REC *rec = tmp->data;

		g_string_truncate(str, 0);
		if (rec->nick != NULL)
			g_string_sprintfa(str, "nick: %s, ", rec->nick);
		if (rec->username != NULL)
			g_string_sprintfa(str, "username: %s, ", rec->username);
		if (rec->realname != NULL)
			g_string_sprintfa(str, "realname: %s, ", rec->realname);
		if (rec->own_host != NULL)
			g_string_sprintfa(str, "host: %s, ", rec->own_host);

		if (rec->cmd_queue_speed > 0)
			g_string_sprintfa(str, "cmdspeed: %d, ", rec->cmd_queue_speed);
		if (rec->max_cmds_at_once > 0)
			g_string_sprintfa(str, "cmdmax: %d, ", rec->max_cmds_at_once);

		if (rec->max_kicks > 0)
			g_string_sprintfa(str, "max_kicks: %d, ", rec->max_kicks);
		if (rec->max_msgs > 0)
			g_string_sprintfa(str, "max_msgs: %d, ", rec->max_msgs);
		if (rec->max_modes > 0)
			g_string_sprintfa(str, "max_modes: %d, ", rec->max_modes);
		if (rec->max_whois > 0)
			g_string_sprintfa(str, "max_whois: %d, ", rec->max_whois);

		if (str->len > 1) g_string_truncate(str, str->len-2);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    IRCTXT_IRCNET_LINE, rec->name, str->str);
	}
	g_string_free(str, TRUE);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_IRCNET_FOOTER);
}

static void cmd_ircnet_add(const char *data)
{
	char *params, *args, *kicks, *msgs, *modes, *whois;
	char *cmdspeed, *cmdmax, *nick, *user, *realname, *host, *name;
	IRCNET_REC *rec;

	args = "kicks msgs modes whois cmdspeed cmdmax nick user realname host";
	params = cmd_get_params(data, 12 | PARAM_FLAG_MULTIARGS, &args,
				&kicks, &msgs, &modes, &whois, &cmdspeed,
				&cmdmax, &nick, &user, &realname, &host, &name);
	if (*name == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = ircnet_find(name);
	if (rec == NULL) {
		rec = g_new0(IRCNET_REC, 1);
		rec->name = g_strdup(name);
	} else {
		if (stristr(args, "-nick")) g_free_and_null(rec->nick);
		if (stristr(args, "-user")) g_free_and_null(rec->username);
		if (stristr(args, "-realname")) g_free_and_null(rec->realname);
		if (stristr(args, "-host")) {
			g_free_and_null(rec->own_host);
                        rec->own_ip = NULL;
		}
	}

	if (stristr(args, "-kicks")) rec->max_kicks = atoi(kicks);
	if (stristr(args, "-msgs")) rec->max_msgs = atoi(msgs);
	if (stristr(args, "-modes")) rec->max_modes = atoi(modes);
	if (stristr(args, "-whois")) rec->max_whois = atoi(whois);

	if (stristr(args, "-cmdspeed")) rec->cmd_queue_speed = atoi(cmdspeed);
	if (stristr(args, "-cmdmax")) rec->max_cmds_at_once = atoi(cmdmax);

	if (*nick != '\0') rec->nick = g_strdup(nick);
	if (*user != '\0') rec->username = g_strdup(user);
	if (*realname != '\0') rec->realname = g_strdup(realname);
	if (*host != '\0') {
		rec->own_host = g_strdup(host);
		rec->own_ip = NULL;
	}

	ircnet_create(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_IRCNET_ADDED, name);

	g_free(params);
}

static void cmd_ircnet_remove(const char *data)
{
	IRCNET_REC *rec;

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = ircnet_find(data);
	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_IRCNET_NOT_FOUND, data);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_IRCNET_REMOVED, data);
		ircnet_destroy(rec);
	}
}

void fe_ircnet_init(void)
{
	command_bind("ircnet", NULL, (SIGNAL_FUNC) cmd_ircnet);
	command_bind("ircnet ", NULL, (SIGNAL_FUNC) cmd_ircnet_list);
	command_bind("ircnet add", NULL, (SIGNAL_FUNC) cmd_ircnet_add);
	command_bind("ircnet remove", NULL, (SIGNAL_FUNC) cmd_ircnet_remove);
}

void fe_ircnet_deinit(void)
{
	command_unbind("ircnet", (SIGNAL_FUNC) cmd_ircnet);
	command_unbind("ircnet ", (SIGNAL_FUNC) cmd_ircnet_list);
	command_unbind("ircnet add", (SIGNAL_FUNC) cmd_ircnet_add);
	command_unbind("ircnet remove", (SIGNAL_FUNC) cmd_ircnet_remove);
}
