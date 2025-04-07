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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>

#include <irssi/src/irc/core/irc-cap.h>
#include <irssi/src/irc/core/irc-servers.h>

int irc_cap_toggle (IRC_SERVER_REC *server, char *cap, int enable)
{
	if (cap == NULL || *cap == '\0')
		return FALSE;

	/* If the negotiation hasn't been completed yet just queue the requests */
	if (!server->cap_complete) {
		if (enable && !i_slist_find_string(server->cap_queue, cap)) {
			server->cap_queue = g_slist_prepend(server->cap_queue, g_strdup(cap));
			return TRUE;
		} else if (!enable && i_slist_find_string(server->cap_queue, cap)) {
			server->cap_queue = i_slist_delete_string(server->cap_queue, cap, g_free);
			return TRUE;
		}

		return FALSE;
	}

	if (enable && !i_slist_find_string(server->cap_active, cap)) {
		/* Make sure the required cap is supported by the server */
		if (!g_hash_table_lookup_extended(server->cap_supported, cap, NULL, NULL))
			return FALSE;

		signal_emit("server cap req", 2, server, cap);
		irc_send_cmdv(server, "CAP REQ %s", cap);
		return TRUE;
	} else if (!enable && i_slist_find_string(server->cap_active, cap)) {
		char *negcap = g_strdup_printf("-%s", cap);

		signal_emit("server cap req", 2, server, negcap);
		irc_send_cmdv(server, "CAP REQ %s", negcap);

		g_free(negcap);
		return TRUE;
	}

	return FALSE;
}

void irc_cap_finish_negotiation (IRC_SERVER_REC *server)
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

static gboolean parse_cap_name(char *name, char **key, char **val)
{
	const char *eq;

	g_return_val_if_fail(name != NULL, FALSE);
	g_return_val_if_fail(name[0] != '\0', FALSE);

	eq = strchr(name, '=');
	/* KEY only value */
	if (eq == NULL) {
		*key = g_strdup(name);
		*val = NULL;
	/* Some values are in a KEY=VALUE form, parse them */
	} else {
		*key = g_strndup(name, (gsize)(eq - name));
		*val = g_strdup(eq + 1);
	}

	return TRUE;
}

static void cap_process_request_queue(IRC_SERVER_REC *server)
{
	/* No CAP has been requested */
	if (server->cap_queue == NULL) {
		irc_cap_finish_negotiation(server);
	} else {
		GSList *tmp;
		GString *cmd;
		int avail_caps = 0;

		cmd = g_string_new("CAP REQ :");

		/* To process the queue in order, we need to reverse the stack once */
		server->cap_queue = g_slist_reverse(server->cap_queue);

		/* Check whether the cap is supported by the server */
		for (tmp = server->cap_queue; tmp != NULL; tmp = tmp->next) {
			if (g_hash_table_lookup_extended(server->cap_supported, tmp->data, NULL,
			                                 NULL)) {
				if (avail_caps > 0)
					g_string_append_c(cmd, ' ');
				g_string_append(cmd, tmp->data);

				avail_caps++;
			}
		}

		/* Clear the queue here */
		i_slist_free_full(server->cap_queue, (GDestroyNotify) g_free);
		server->cap_queue = NULL;

		/* If the server doesn't support any cap we requested close the negotiation here */
		if (avail_caps > 0) {
			signal_emit("server cap req", 2, server,
			            cmd->str + sizeof("CAP REQ :") - 1);
			irc_send_cmd_now(server, cmd->str);
		} else {
			irc_cap_finish_negotiation(server);
		}

		g_string_free(cmd, TRUE);
	}
}

static void event_cap (IRC_SERVER_REC *server, char *args, char *nick, char *address)
{
	char *params, *evt, *list, *star, **caps;
	int i, caps_length, disable, multiline;

	params = event_get_params(args, 4, NULL, &evt, &star, &list);
	if (params == NULL)
		return;

	/* Multiline responses have an additional parameter and we have to do
	 * this stupid dance to parse them */
	if (!g_ascii_strcasecmp(evt, "LS") && !strcmp(star, "*")) {
		multiline = TRUE;
	}
	/* This branch covers the '*' parameter isn't present, adjust the
	 * parameter pointer to compensate for this */
	else if (list[0] == '\0') {
		multiline = FALSE;
		list = star;
	}
	/* Malformed request, terminate the negotiation */
	else {
		irc_cap_finish_negotiation(server);
		g_free(params);
		g_warn_if_reached();
		return;
	}

	/* The table is created only when needed */
	if (server->cap_supported == NULL) {
		server->cap_supported = g_hash_table_new_full(g_str_hash,
							      g_str_equal,
							      g_free, g_free);
	}

	/* Strip the trailing whitespaces before splitting the string, some servers send responses with
	 * superfluous whitespaces that g_strsplit the interprets as tokens */
	caps = g_strsplit(g_strchomp(list), " ", -1);
	caps_length = g_strv_length(caps);

	if (!g_ascii_strcasecmp(evt, "LS")) {
		if (!server->cap_in_multiline) {
			/* Throw away everything and start from scratch */
			g_hash_table_remove_all(server->cap_supported);
		}

		server->cap_in_multiline = multiline;

		/* Create a list of the supported caps */
		for (i = 0; i < caps_length; i++) {
			char *key, *val;

			if (!parse_cap_name(caps[i], &key, &val)) {
				g_warning("Invalid CAP %s key/value pair", evt);
				continue;
			}

			if (g_hash_table_lookup_extended(server->cap_supported, key, NULL, NULL)) {
				/* The specification doesn't say anything about
				 * duplicated values, let's just warn the user */
				g_warning("The server sent the %s capability twice", key);
			}
			g_hash_table_replace(server->cap_supported, key, val);
		}

		/* A multiline response is always terminated by a normal one,
		 * wait until we receive that one to require any CAP */
		if (multiline == FALSE) {
			gboolean want_starttls =
			    i_slist_find_string(server->cap_queue, CAP_STARTTLS) != NULL;
			server->cap_queue =
			    i_slist_delete_string(server->cap_queue, CAP_STARTTLS, g_free);
			if (server->connrec->starttls) {
				/* the connection has requested starttls,
				   no more data must be sent now */
			} else if (want_starttls &&
			           g_hash_table_lookup_extended(server->cap_supported, CAP_STARTTLS,
			                                        NULL, NULL)) {
				irc_server_send_starttls(server);
				/* no more data must be sent now */
			} else {
				cap_process_request_queue(server);
			}
		}
	}
	else if (!g_ascii_strcasecmp(evt, "ACK")) {
		int got_sasl = (i_slist_find_string(server->cap_active, "sasl") != NULL);

		/* Emit a signal for every ack'd cap */
		for (i = 0; i < caps_length; i++) {
			disable = (*caps[i] == '-');

			if (disable)
				server->cap_active =
				    i_slist_delete_string(server->cap_active, caps[i] + 1, g_free);
			else if (!i_slist_find_string(server->cap_active, caps[i]))
				server->cap_active = g_slist_prepend(server->cap_active, g_strdup(caps[i]));

			if (!strcmp(caps[i], "sasl"))
				got_sasl = TRUE;

			cap_emit_signal(server, "ack", caps[i]);
		}

		/* Hopefully the server has ack'd all the caps requested and we're ready to terminate the
		 * negotiation, unless sasl was requested. In this case we must not terminate the negotiation
		 * until the sasl handshake is over. */
		if (got_sasl == FALSE)
			irc_cap_finish_negotiation(server);
	}
	else if (!g_ascii_strcasecmp(evt, "NAK")) {
		g_warning("The server answered with a NAK to our CAP request, this should not happen");

		/* A NAK'd request means that a required cap can't be enabled or disabled, don't update the
		 * list of active caps and notify the listeners. */
		for (i = 0; i < caps_length; i++)
			cap_emit_signal(server, "nak", caps[i]);
	}
	else if (!g_ascii_strcasecmp(evt, "NEW")) {
		for (i = 0; i < caps_length; i++) {
			char *key, *val;

			if (!parse_cap_name(caps[i], &key, &val)) {
				g_warning("Invalid CAP %s key/value pair", evt);
				continue;
			}

			g_hash_table_replace(server->cap_supported, key, val);
			cap_emit_signal(server, "new", key);
		}
	}
	else if (!g_ascii_strcasecmp(evt, "DEL")) {
		for (i = 0; i < caps_length; i++) {
			char *key, *val;

			if (!parse_cap_name(caps[i], &key, &val)) {
				g_warning("Invalid CAP %s key/value pair", evt);
				continue;
			}

			g_hash_table_remove(server->cap_supported, key);
			cap_emit_signal(server, "delete", key);
			/* The server removed this CAP, remove it from the list
			 * of the active ones if we had requested it */
			server->cap_active = i_slist_delete_string(server->cap_active, key, g_free);
			/* We don't transfer the ownership of those two
			 * variables this time, just free them when we're done. */
			g_free(key);
			g_free(val);
		}
	}
	else if (!g_ascii_strcasecmp(evt, "LIST")) {
		/* do nothing, fe-cap will handle it */
	}
	else {
		g_warning("Unhandled CAP subcommand %s", evt);
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

void irc_cap_init (void)
{
	signal_add_last("server cap continue", (SIGNAL_FUNC) cap_process_request_queue);
	signal_add_first("event cap", (SIGNAL_FUNC) event_cap);
	signal_add_first("event 410", (SIGNAL_FUNC) event_invalid_cap);
}

void irc_cap_deinit (void)
{
	signal_remove("server cap continue", (SIGNAL_FUNC) cap_process_request_queue);
	signal_remove("event cap", (SIGNAL_FUNC) event_cap);
	signal_remove("event 410", (SIGNAL_FUNC) event_invalid_cap);
}
