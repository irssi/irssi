/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
 *
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
 *               2012  David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#define _GNU_SOURCE
#include <glib.h>

#include "module.h"

#include <irssi/src/common.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/commands.h>

#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-queries.h>
#include <irssi/src/irc/core/irc-commands.h>

#include <irssi/src/otr/key.h>
#include <irssi/src/otr/otr.h>
#include <irssi/src/otr/otr-formats.h>
#include <irssi/src/otr/otr-fe.h>
#include <irssi/src/core/misc.h>

/*
 * Global state for the user. Init when the module loads.
 */
struct otr_user_state *user_state_global;

/*
 * Pipes all outgoing private messages through OTR
 */
static void sig_server_sendmsg(SERVER_REC *server, const char *target,
		const char *msg, void *target_type_p)
{
	char *otrmsg = NULL;

	if (GPOINTER_TO_INT(target_type_p) != SEND_TARGET_NICK) {
		otrl_message_free(otrmsg);
		return;
	}

	/* Critical section. On error, message MUST NOT be sent */
	if (otr_send(server, msg, target, &otrmsg)) {
		signal_stop();
		otrl_message_free(otrmsg);
		return;
	}

	if (otrmsg == NULL) {
		/* Send original message */
		signal_continue(4, server, target, msg, target_type_p);
	} else {
		/* Send encrypted message */
		signal_continue(4, server, target, otrmsg, target_type_p);
	}

	otrl_message_free(otrmsg);
}

/*
 * Pipes all incoming private messages through OTR
 */
void sig_message_private(SERVER_REC *server, const char *msg, const char *nick, const char *address, const char *target)
{
	char *new_msg = NULL;

	if (otr_receive(server, msg, nick, &new_msg)) {
		signal_stop();
		otrl_message_free(new_msg);
		return;
	}

	if (new_msg == NULL) {
		/* This message was not OTR */
		signal_continue(5, server, msg, nick, address, target);
	} else {
		/*
		 * Check for /me IRC marker and if so, handle it so the user does not
		 * receive a message beginning with /me but rather let irssi handle it
		 * as a IRC action.
		 */
		if (strncmp(new_msg, OTR_IRC_MARKER_ME, OTR_IRC_MARKER_ME_LEN) == 0) {
			signal_stop();
			signal_emit("message irc action", 5, server, new_msg + OTR_IRC_MARKER_ME_LEN, nick, address, nick);
		} else {
			/* OTR received message */
			signal_continue(5, server, new_msg, nick, address, target);
		}
	}

	otrl_message_free(new_msg);
}

/*
 * Finish an OTR conversation when its query is closed.
 */
static void sig_query_destroyed(QUERY_REC *query)
{
	if (query && query->server && query->server->connrec) {
		otr_finish(query->server, query->name);
	}
}

/*
 * Handle /me IRC command.
 */
static void cmd_me(const char *data, IRC_SERVER_REC *server,
		WI_ITEM_REC *item)
{
	const char *target;
	char *msg, *otrmsg = NULL;
	QUERY_REC *query;

	query = QUERY(item);

	if (query == NULL || query->server == NULL) {
		return;
	}

	CMD_IRC_SERVER(server);
	if (!IS_IRC_QUERY(query)) {
		return;
	}

	if (server == NULL || !server->connected) {
		cmd_return_error(CMDERR_NOT_CONNECTED);
	}

	target = window_item_get_target(item);

	msg = g_strdup_printf(OTR_IRC_MARKER_ME "%s", data);
	g_return_if_fail(msg != NULL);

	/* Critical section. On error, message MUST NOT be sent */
	otr_send(query->server, msg, target, &otrmsg);
	g_free(msg);

	if (otrmsg == NULL) {
		return;
	}

	signal_stop();

	if (otrmsg) {
		/* Send encrypted message */
		otr_send_message(SERVER(server), target, otrmsg);
		otrl_message_free(otrmsg);
	}

	signal_emit("message irc own_action", 3, server, data, item->visible_name);
}

/*
 * Optionally finish conversations on /quit. We're already doing this on unload
 * but the quit handler terminates irc connections before unloading.
 */
static void cmd_quit(const char *data, void *server, WI_ITEM_REC *item)
{
	otr_finishall(user_state_global);
}

/*
 * Create otr module directory if none exists.
 */
static void create_module_dir(void)
{
	char *dir_path = NULL;
	struct stat statbuf;

	/* Create ~/.irssi/otr directory. */
	dir_path = g_strdup_printf("%s/%s", get_irssi_dir(), OTR_DIR);
	g_return_if_fail(dir_path != NULL);

	if (stat(dir_path, &statbuf) != 0) {
		if (g_mkdir_with_parents(dir_path, 0700) != 0)
			g_warning("Unable to create OTR directory path.");
	} else if (!S_ISDIR(statbuf.st_mode)) {
		g_warning("%s is not a directory.", dir_path);
		g_warning("You should remove it with command: rm %s", dir_path);
	}

	g_free(dir_path);
}

void otr_send_message(SERVER_REC *server, const char *recipient, const char *msg)
{
	/*
	 * Apparently, there are cases where the server record is NULL which has
	 * been reported with the irssi xmpp plugin. In that case, just return an
	 * do nothing.
	 */
	g_return_if_fail(server != NULL);

	server->send_message(server, recipient, msg, GPOINTER_TO_INT(SEND_TARGET_NICK));
}

/*
 * irssi init()
 */
void otr_core_init(void)
{
	module_register("otr", "core");

	create_module_dir();

	otr_lib_init();

	user_state_global = otr_init_user_state();
	g_return_if_fail(user_state_global != NULL);

	signal_add_first("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);

	command_bind_first("quit", NULL, (SIGNAL_FUNC) cmd_quit);
	command_bind_irc_first("me", NULL, (SIGNAL_FUNC) cmd_me);

	otr_fe_init();
}

/*
 * irssi deinit()
 */
void otr_core_deinit(void)
{
	signal_remove("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);

	otr_fe_deinit();

	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);

	otr_finishall(user_state_global);

	/* Remove glib timer if any. */
	otr_control_timer(0, NULL);

	otr_free_user_state(user_state_global);

	otr_lib_uninit();
}

void otr_core_abicheck(int *version)
{
	*version = IRSSI_ABI_VERSION;
}
