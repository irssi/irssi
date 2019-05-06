/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
 *
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
 *               2012  David Goulet <dgoulet@ev0ke.net>
 *               2014  Alexander Færøy <ahf@0x90.dk>
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

#include <irssi/src/common.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-queries.h>
#include <irssi/src/fe-text/statusbar-item.h>

#include <irssi/src/otr/otr.h>
#include <irssi/src/otr/otr-formats.h>
#include <irssi/src/otr/key.h>

static void cmd_otr(const char *data, SERVER_REC *server, void *item)
{
	if (*data == '\0')
		data = "info"; // FIXME(ahf): Is this really what we want as default?

	command_runsub("otr", data, server, item);

	// We always redraw the OTR statusbar, just in case.
	statusbar_items_redraw("otr");
}

static void cmd_otr_debug(const char *data)
{
	otr_debug_toggle();

	if (otr_debug_get())
		printtext(NULL, NULL, MSGLEVEL_CRAP, "OTR debugging enabled");
	else
		printtext(NULL, NULL, MSGLEVEL_CRAP, "OTR debugging disabled");
}

static void cmd_otr_init(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;
	ConnContext *ctx;

	g_return_if_fail(server != NULL);

	if (!server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!IS_QUERY(item))
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	query = QUERY(item);
	target = query->name;

	ctx = otr_find_context(server, target, FALSE);
	if (ctx && ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
		printformat(server, target, MSGLEVEL_CRAP, TXT_OTR_SESSION_ALREADY_SECURED, ctx->accountname);
		return;
	}

	printformat(server, target, MSGLEVEL_CRAP, TXT_OTR_SESSION_INITIATING);

	/*
	 * Irssi does not handle well the HTML tag in the default OTR query message
	 * so just send the OTR tag instead. Contact me for a better fix! :)
	 */
	otr_send_message(server, target, "?OTRv23?");
}

static void cmd_otr_finish(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	g_return_if_fail(server != NULL);

	if (!server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!IS_QUERY(item))
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	query = QUERY(item);
	target = query->name;

	otr_finish(server, target);
}

static void cmd_otr_trust(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	char *fingerprint, *human_fingerprint;
	void *free_arg;

	g_return_if_fail(server != NULL);

	query = QUERY(item);
	target = query ? query->name : NULL;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST, &fingerprint))
		return;

	// We fallback to target if fingerprint isn't specified.
	if (*fingerprint == '\0' && target == NULL)
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	human_fingerprint = g_ascii_strup(fingerprint, -1);
	otr_trust(server, target, human_fingerprint, user_state_global);
	g_free(human_fingerprint);

	cmd_params_free(free_arg);
}

static void cmd_otr_distrust(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	char *fingerprint, *human_fingerprint;
	void *free_arg;

	g_return_if_fail(server != NULL);

	query = QUERY(item);
	target = query ? query->name : NULL;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST, &fingerprint))
		return;

	// We fallback to target if fingerprint isn't specified.
	if (*fingerprint == '\0' && target == NULL)
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	human_fingerprint = g_ascii_strup(fingerprint, -1);
	otr_distrust(server, target, human_fingerprint, user_state_global);
	g_free(human_fingerprint);

	cmd_params_free(free_arg);
}

static void cmd_otr_forget(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	char *fingerprint, *human_fingerprint;
	void *free_arg;

	g_return_if_fail(server != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_GETREST, &fingerprint))
		return;

	query = QUERY(item);
	target = query ? query->name : NULL;

	// We fallback to target if fingerprint isn't specified.
	if (*fingerprint == '\0' && target == NULL)
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	human_fingerprint = g_ascii_strup(fingerprint, -1);
	otr_forget(server, target, human_fingerprint, user_state_global);
	g_free(human_fingerprint);

	cmd_params_free(free_arg);
}

static void cmd_otr_authabort(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	query = QUERY(item);
	target = query ? query->name : NULL;

	if (server == NULL || target == NULL)
		cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	otr_auth_abort(server, target);
}

static void cmd_otr_auth(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	char *secret;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &secret))
		return;

	query = QUERY(item);
	target = query ? query->name : NULL;

	if (server == NULL || target == NULL || *secret == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	if (*secret == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	otr_auth(server, target, NULL, secret);

	cmd_params_free(free_arg);
}

static void cmd_otr_authq(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	QUERY_REC *query;
	char *target;

	char *question, *secret;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 2, &question, &secret))
		return;

	query = QUERY(item);
	target = query ? query->name : NULL;

	if (server == NULL || target == NULL || *question == '\0' || *secret == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	otr_auth(server, target, question, secret);

	cmd_params_free(free_arg);
}

static void cmd_otr_genkey(const char *data)
{
	char *account_name;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &account_name))
		return;

	if (*account_name == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	key_gen_run(user_state_global, account_name);

	cmd_params_free(free_arg);
}

static void cmd_otr_contexts(const char *data)
{
	otr_contexts(user_state_global);
}

static void cmd_otr_info(const char *data)
{
	gboolean empty = TRUE;
	char ownfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	OtrlPrivKey *key;

	for (key = user_state_global->otr_state->privkey_root; key != NULL; key = key->next) {
		otrl_privkey_fingerprint(user_state_global->otr_state, ownfp, key->accountname, OTR_PROTOCOL_ID);

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_OTR_FP_NICK, key->accountname, ownfp);

		empty = FALSE;
	}

	if (empty)
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_OTR_KEYS_UNAVAILABLE);
}

static void statusbar_otr(struct SBAR_ITEM_REC *item, int get_size_only)
{
	WI_ITEM_REC *wi_item = active_win->active;
	QUERY_REC *query = QUERY(wi_item);
	enum otr_status_format format = TXT_OTR_MODULE_NAME;

	if (query && query->server && query->server->connrec) {
		format = otr_get_status_format(query->server, query->name);
	}

	statusbar_item_default_handler(item, get_size_only,
			format ? fe_otr_formats[format].def : "", " ", FALSE);
}

void otr_fe_init(void)
{
	theme_register(fe_otr_formats);

	command_bind("otr", NULL, (SIGNAL_FUNC) cmd_otr);
	command_bind("otr debug", NULL, (SIGNAL_FUNC) cmd_otr_debug);
	command_bind("otr init", NULL, (SIGNAL_FUNC) cmd_otr_init);
	command_bind("otr finish", NULL, (SIGNAL_FUNC) cmd_otr_finish);
	command_bind("otr trust", NULL, (SIGNAL_FUNC) cmd_otr_trust);
	command_bind("otr distrust", NULL, (SIGNAL_FUNC) cmd_otr_distrust);
	command_bind("otr forget", NULL, (SIGNAL_FUNC) cmd_otr_forget);
	command_bind("otr authabort", NULL, (SIGNAL_FUNC) cmd_otr_authabort);
	command_bind("otr auth", NULL, (SIGNAL_FUNC) cmd_otr_auth);
	command_bind("otr authq", NULL, (SIGNAL_FUNC) cmd_otr_authq);
	command_bind("otr genkey", NULL, (SIGNAL_FUNC) cmd_otr_genkey);
	command_bind("otr contexts", NULL, (SIGNAL_FUNC) cmd_otr_contexts);
	command_bind("otr info", NULL, (SIGNAL_FUNC) cmd_otr_info);

	statusbar_item_register("otr", NULL, statusbar_otr);
	statusbar_items_redraw("window");
}

void otr_fe_deinit(void)
{
	theme_unregister();

	command_unbind("otr", (SIGNAL_FUNC) cmd_otr);
	command_unbind("otr debug", (SIGNAL_FUNC) cmd_otr_debug);
	command_unbind("otr init", (SIGNAL_FUNC) cmd_otr_init);
	command_unbind("otr finish", (SIGNAL_FUNC) cmd_otr_finish);
	command_unbind("otr trust", (SIGNAL_FUNC) cmd_otr_trust);
	command_unbind("otr distrust", (SIGNAL_FUNC) cmd_otr_distrust);
	command_unbind("otr forget", (SIGNAL_FUNC) cmd_otr_forget);
	command_unbind("otr authabort", (SIGNAL_FUNC) cmd_otr_authabort);
	command_unbind("otr auth", (SIGNAL_FUNC) cmd_otr_auth);
	command_unbind("otr authq", (SIGNAL_FUNC) cmd_otr_authq);
	command_unbind("otr genkey", (SIGNAL_FUNC) cmd_otr_genkey);
	command_unbind("otr contexts", (SIGNAL_FUNC) cmd_otr_contexts);
	command_unbind("otr info", (SIGNAL_FUNC) cmd_otr_info);

	statusbar_item_unregister("otr");
}
