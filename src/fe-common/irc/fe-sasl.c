/*
    fe-sasl.c : irssi

    Copyright (C) 2015-2017 The Lemon Man

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
#include "levels.h"
#include "misc.h"
#include "sasl.h"

#include "irc-servers.h"
#include "settings.h"

#include "printtext.h"

static void sig_sasl_success(IRC_SERVER_REC *server)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_SASL_SUCCESS);
}

static void sig_sasl_failure(IRC_SERVER_REC *server, const char *reason)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_SASL_ERROR, reason);
}

static void sig_cap_end(IRC_SERVER_REC *server)
{
	/* The negotiation has now been terminated, if we didn't manage to
	 * authenticate successfully with the server just disconnect. */
	if (!server->sasl_success &&
	    server->connrec->sasl_mechanism != SASL_MECHANISM_NONE &&
	    settings_get_bool("sasl_disconnect_on_failure")) {
		/* We can't use server_disconnect() here because we'd end up
		 * freeing the 'server' object and be guilty of a slew of UaF. */
		server->connection_lost = TRUE;
		/* By setting connection_lost we make sure the communication is
		 * halted and when the control goes back to irc_parse_incoming
		 * the server object is safely destroyed. */
		signal_stop();
	}

}

void fe_sasl_init(void)
{
	settings_add_bool("server", "sasl_disconnect_on_failure", TRUE);

	signal_add("server sasl success", (SIGNAL_FUNC) sig_sasl_success);
	signal_add("server sasl failure", (SIGNAL_FUNC) sig_sasl_failure);
	signal_add_first("server cap end", (SIGNAL_FUNC) sig_cap_end);
}

void fe_sasl_deinit(void)
{
	signal_remove("server sasl success", (SIGNAL_FUNC) sig_sasl_success);
	signal_remove("server sasl failure", (SIGNAL_FUNC) sig_sasl_failure);
	signal_remove("server cap end", (SIGNAL_FUNC) sig_cap_end);
}
