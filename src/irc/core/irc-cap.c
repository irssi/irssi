/*  irc-cap.c : irssi

    Copyright (C) 2015 The Lemon Man

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
#include "signals.h"
#include "misc.h"

#include "irc-cap.h"
#include "irc-servers.h"

int cap_toggle (IRC_SERVER_REC *server, char *cap, int enable)
{
	if (cap == NULL || *cap == '\0')
		return FALSE;

	/* If the negotiation hasn't been completed yet just queue the requests */
	if (!server->cap_complete) {
		if (enable && !gslist_find_string(server->cap_queue, cap)) {
			server->cap_queue = g_slist_prepend(server->cap_queue, g_strdup(cap));
			return TRUE;
		}
		else if (!enable && gslist_find_string(server->cap_queue, cap)) {
			server->cap_queue = gslist_remove_string(server->cap_queue, cap);
			return TRUE;
		}

		return FALSE;
	}

	if (enable && !gslist_find_string(server->cap_active, cap)) {
		/* Make sure the required cap is supported by the server */
		if (!gslist_find_string(server->cap_supported, cap))
			return FALSE;

		irc_send_cmdv(server, "CAP REQ %s", cap);
		return TRUE;
	}
	else if (!enable && gslist_find_string(server->cap_active, cap)) {
		irc_send_cmdv(server, "CAP REQ -%s", cap);
		return TRUE;
	}

	return FALSE;
}

void cap_finish_negotiation (IRC_SERVER_REC *server)
{
	if (server->cap_complete)
		return;

	server->cap_complete = TRUE;
	irc_send_cmd_now(server, "CAP END");

	signal_emit("server cap end", 1, server);
}

static void cap_emit_signal (IRC_SERVER_REC *server, char *cmd, char *args)
{
	char *signal_name;

	signal_name = g_strdup_printf("server cap %s %s", cmd, args? args: "");
	signal_emit(signal_name, 1, server);
	g_free(signal_name);
}

static void event_cap (IRC_SERVER_REC *server, char *args, char *nick, char *address)
{
	GSList *tmp;
	GString *cmd;
	char *params, *evt, *list, **caps;
	int i, caps_length, disable, avail_caps;

	params = event_get_params(args, 3, NULL, &evt, &list);
	if (params == NULL)
		return;

	/* Strip the trailing whitespaces before splitting the string, some servers send responses with
	 * superfluous whitespaces that g_strsplit the interprets as tokens */
	caps = g_strsplit(g_strchomp(list), " ", -1);
	caps_length = g_strv_length(caps);

	if (!g_strcmp0(evt, "LS")) {
		/* Create a list of the supported caps */
		for (i = 0; i < caps_length; i++)
			server->cap_supported = g_slist_prepend(server->cap_supported, g_strdup(caps[i]));

		/* Request the required caps, if any */
		if (server->cap_queue == NULL) {
			cap_finish_negotiation(server);
		}
		else {
			cmd = g_string_new("CAP REQ :");

			avail_caps = 0;

			/* Check whether the cap is supported by the server */
			for (tmp = server->cap_queue; tmp != NULL; tmp = tmp->next) {
				if (gslist_find_string(server->cap_supported, tmp->data)) {
					if (avail_caps > 0)
						g_string_append_c(cmd, ' ');
					g_string_append(cmd, tmp->data);

					avail_caps++;
				}
			}

			/* Clear the queue here */
			gslist_free_full(server->cap_queue, (GDestroyNotify) g_free);
			server->cap_queue = NULL;

			/* If the server doesn't support any cap we requested close the negotiation here */
			if (avail_caps > 0)
				irc_send_cmd_now(server, cmd->str);
			else
				cap_finish_negotiation(server);

			g_string_free(cmd, TRUE);
		}
	}
	else if (!g_strcmp0(evt, "ACK")) {
		int got_sasl = FALSE;

		/* Emit a signal for every ack'd cap */
		for (i = 0; i < caps_length; i++) {
			disable = (*caps[i] == '-');

			if (disable)
				server->cap_active = gslist_remove_string(server->cap_active, caps[i] + 1);
			else
				server->cap_active = g_slist_prepend(server->cap_active, g_strdup(caps[i]));

			if (!g_strcmp0(caps[i], "sasl"))
				got_sasl = TRUE;

			cap_emit_signal(server, "ack", caps[i]);
		}

		/* Hopefully the server has ack'd all the caps requested and we're ready to terminate the
		 * negotiation, unless sasl was requested. In this case we must not terminate the negotiation
		 * until the sasl handshake is over. */
		if (got_sasl == FALSE)
			cap_finish_negotiation(server);
	}
	else if (!g_strcmp0(evt, "NAK")) {
		g_warning("The server answered with a NAK to our CAP request, this should not happen");

		/* A NAK'd request means that a required cap can't be enabled or disabled, don't update the
		 * list of active caps and notify the listeners. */
		for (i = 0; i < caps_length; i++)
			cap_emit_signal(server, "nak", caps[i]);
	}

	g_strfreev(caps);
	g_free(params);
}

static void event_invalid_cap (IRC_SERVER_REC *server, const char *data, const char *from)
{
	/* The server didn't understand one (or more) requested caps, terminate the negotiation.
	 * This could be handled in a graceful way but since it shouldn't really ever happen this seems a
	 * good way to deal with 410 errors. */
	server->cap_complete = FALSE;
	irc_send_cmd_now(server, "CAP END");
}

void cap_init (void)
{
	signal_add_first("event cap", (SIGNAL_FUNC) event_cap);
	signal_add_first("event 410", (SIGNAL_FUNC) event_invalid_cap);
}

void cap_deinit (void)
{
	signal_remove("event cap", (SIGNAL_FUNC) event_cap);
	signal_remove("event 410", (SIGNAL_FUNC) event_invalid_cap);
}
