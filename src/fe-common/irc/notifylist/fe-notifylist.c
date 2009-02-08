/*
 fe-notifylist.c : irssi

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
#include "chatnets.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "levels.h"
#include "irc-servers.h"
#include "irc-chatnets.h"
#include "irc/notifylist/notifylist.h"

#include "themes.h"
#include "printtext.h"

/* add the nick of a hostmask to list if it isn't there already */
static GSList *mask_add_once(GSList *list, const char *mask)
{
	char *str, *ptr;

	g_return_val_if_fail(mask != NULL, NULL);

	ptr = strchr(mask, '!');
	str = ptr == NULL ? g_strdup(mask) :
		g_strndup(mask, (int) (ptr-mask));

	if (gslist_find_icase_string(list, str) == NULL)
		return g_slist_append(list, str);

	g_free(str);
	return list;
}

/* search for online people, print them and update offline list */
static void print_notify_onserver(IRC_SERVER_REC *server, GSList *nicks,
				  GSList **offline, const char *desc)
{
	GSList *tmp;
	GString *str;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(offline != NULL);
	g_return_if_fail(desc != NULL);

	str = g_string_new(NULL);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		char *nick = tmp->data;

		if (!notifylist_ison_server(server, nick))
			continue;

		g_string_append_printf(str, "%s, ", nick);
		*offline = g_slist_remove(*offline, nick);
	}

	if (str->len > 0) {
		g_string_truncate(str, str->len-2);
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_NOTIFY_ONLINE, desc, str->str);
	}

	g_string_free(str, TRUE);
}

/* show the notify list, displaying who is on which net */
static void cmd_notify_show(void)
{
	GSList *nicks, *offline, *tmp;
	IRC_SERVER_REC *server;

	if (notifies == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_NOTIFY_LIST_EMPTY);
		return;
	}

	/* build a list containing only the nicks */
	nicks = NULL;
	for (tmp = notifies; tmp != NULL; tmp = tmp->next) {
		NOTIFYLIST_REC *rec = tmp->data;

		nicks = mask_add_once(nicks, rec->mask);
	}
	offline = g_slist_copy(nicks);

        /* print the notifies on specific ircnets */
	for (tmp = chatnets; tmp != NULL; tmp = tmp->next) {
		IRC_CHATNET_REC *rec = tmp->data;

		if (!IS_IRCNET(rec))
			continue;

		server = (IRC_SERVER_REC *) server_find_chatnet(rec->name);
		if (!IS_IRC_SERVER(server))
			continue;

		print_notify_onserver(server, nicks, &offline, rec->name);
	}

	/* print the notifies on servers without a specified ircnet */
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		server = tmp->data;

		if (!IS_IRC_SERVER(server) || server->connrec->chatnet != NULL)
			continue;
		print_notify_onserver(server, nicks, &offline, server->tag);
	}

	/* print offline people */
	if (offline != NULL) {
		GString *str;

		str = g_string_new(NULL);
		for (tmp = offline; tmp != NULL; tmp = tmp->next)
			g_string_append_printf(str, "%s, ", (char *) tmp->data);

		g_string_truncate(str, str->len-2);
		printformat(NULL,NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_NOTIFY_OFFLINE, str->str);
		g_string_free(str, TRUE);

		g_slist_free(offline);
	}

	g_slist_foreach(nicks, (GFunc) g_free, NULL);
	g_slist_free(nicks);
}

static void notifylist_print(NOTIFYLIST_REC *rec)
{
	char *ircnets;

	ircnets = rec->ircnets == NULL ? NULL :
		g_strjoinv(",", rec->ircnets);

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_NOTIFY_LIST,
		    rec->mask, ircnets != NULL ? ircnets : "",
		    rec->away_check ? "-away" : "");

	g_free_not_null(ircnets);
}

static void cmd_notifylist_show(void)
{
	if (notifies == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_NOTIFY_LIST_EMPTY);
	} else {
		g_slist_foreach(notifies, (GFunc) notifylist_print, NULL);
	}
}

static void cmd_notify(const char *data)
{
	if (*data == '\0') {
		cmd_notify_show();
		signal_stop();
	}

	if (g_ascii_strncasecmp(data, "-list", 4) == 0) {
		cmd_notifylist_show();
		signal_stop();
	}
}

static void notifylist_joined(IRC_SERVER_REC *server, const char *nick,
			      const char *username, const char *host,
			      const char *realname, const char *awaymsg)
{
	g_return_if_fail(nick != NULL);

	printformat(server, nick, MSGLEVEL_CLIENTNOTICE,
		    IRCTXT_NOTIFY_JOIN, nick, username, host, realname,
		    server->connrec->chatnet == NULL ? "IRC" : server->connrec->chatnet);
}

static void notifylist_left(IRC_SERVER_REC *server, const char *nick,
			    const char *username, const char *host,
			    const char *realname, const char *awaymsg)
{
	g_return_if_fail(nick != NULL);

	printformat(server, nick, MSGLEVEL_CLIENTNOTICE, IRCTXT_NOTIFY_PART,
		    nick, username, host, realname,
		    server->connrec->chatnet == NULL ? "IRC" : server->connrec->chatnet);
}

static void notifylist_away(IRC_SERVER_REC *server, const char *nick,
			    const char *username, const char *host,
			    const char *realname, const char *awaymsg)
{
	g_return_if_fail(nick != NULL);

	if (awaymsg != NULL) {
		printformat(server, nick, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_NOTIFY_AWAY, nick, username, host, realname, awaymsg,
			    server->connrec->chatnet == NULL ? "IRC" : server->connrec->chatnet);
	} else {
		printformat(server, nick, MSGLEVEL_CLIENTNOTICE,
			    IRCTXT_NOTIFY_UNAWAY, nick, username, host, realname,
			    server->connrec->chatnet == NULL ? "IRC" : server->connrec->chatnet);
	}
}

void fe_irc_notifylist_init(void)
{
	theme_register(fecommon_irc_notifylist_formats);

	command_bind("notify", NULL, (SIGNAL_FUNC) cmd_notify);
	signal_add("notifylist joined", (SIGNAL_FUNC) notifylist_joined);
	signal_add("notifylist left", (SIGNAL_FUNC) notifylist_left);
	signal_add("notifylist away changed", (SIGNAL_FUNC) notifylist_away);

	command_set_options("notify", "list");

	settings_check();
	module_register("notifylist", "fe-irc");
}

void fe_irc_notifylist_deinit(void)
{
	theme_unregister();

	command_unbind("notify", (SIGNAL_FUNC) cmd_notify);
	signal_remove("notifylist joined", (SIGNAL_FUNC) notifylist_joined);
	signal_remove("notifylist left", (SIGNAL_FUNC) notifylist_left);
	signal_remove("notifylist away changed", (SIGNAL_FUNC) notifylist_away);
}
