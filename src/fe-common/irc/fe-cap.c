/*
    fe-cap.c : irssi

    Copyright (C) 2018 dequis

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
#include <irssi/src/fe-common/irc/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-servers.h>

#include <irssi/src/fe-common/core/printtext.h>

static const struct {
	const char *command;
	const int template;
} fe_cap_messages[] = {
	{"LS", IRCTXT_CAP_LS},
	{"ACK", IRCTXT_CAP_ACK},
	{"NAK", IRCTXT_CAP_NAK},
	{"LIST", IRCTXT_CAP_LIST},
	{"NEW", IRCTXT_CAP_NEW},
	{"DEL", IRCTXT_CAP_DEL},
};

static void event_cap(IRC_SERVER_REC *server, char *args, char *nick, char *address)
{
	int i;
	char *params, *evt, *list, *star;

	params = event_get_params(args, 4, NULL, &evt, &star, &list);

	if (params == NULL) {
		return;
	}

	/* With multiline CAP LS, if the '*' parameter isn't present,
	 * adjust the parameter pointer to compensate for this */
	if (strcmp(star, "*") != 0 && list[0] == '\0') {
		list = star;
	}

	for (i = 0; i < G_N_ELEMENTS(fe_cap_messages); i++) {
		if (!g_ascii_strcasecmp(evt, fe_cap_messages[i].command)) {
			printformat(server, NULL, MSGLEVEL_CRAP, fe_cap_messages[i].template, list);
		}
	}

	g_free(params);
}

static void sig_server_cap_req(IRC_SERVER_REC *server, char *caps)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_CAP_REQ, caps);
}

void fe_cap_init(void)
{
	signal_add("event cap", (SIGNAL_FUNC) event_cap);
	signal_add("server cap req", (SIGNAL_FUNC) sig_server_cap_req);
}

void fe_cap_deinit(void)
{
	signal_remove("event cap", (SIGNAL_FUNC) event_cap);
	signal_remove("server cap req", (SIGNAL_FUNC) sig_server_cap_req);
}
