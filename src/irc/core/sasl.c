/*
    fe-sasl.c : irssi

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
#include "misc.h"
#include "settings.h"

#include "irc-cap.h"
#include "irc-servers.h"
#include "sasl.h"

#define SASL_TIMEOUT (20 * 1000) // ms

static GSList *sasl_mechanisms;
static GHashTable *sasl_buffers;

void sasl_mechanism_register(const char *name)
{
	if (gslist_find_string(sasl_mechanisms, name) == NULL) {
		sasl_mechanisms = g_slist_append(sasl_mechanisms, g_strdup(name));
	}
}

void sasl_mechanism_unregister(const char *name)
{
	GSList *pos;

	pos = gslist_find_string(sasl_mechanisms, name);
	if (pos != NULL) {
		g_free(pos->data);
		sasl_mechanisms = g_slist_remove(sasl_mechanisms, pos->data);
	}
}

static gboolean is_registered_mechanism(const char *name)
{
	return gslist_find_string(sasl_mechanisms, name) != NULL;
}

static void sasl_emit_abort_signal(IRC_SERVER_REC *server)
{
	IRC_SERVER_CONNECT_REC *conn;

	conn = server->connrec;

	if (is_registered_mechanism(conn->sasl_mechanism)) {
		char *str;

		str = g_strconcat("server sasl abort ", conn->sasl_mechanism, NULL);
		ascii_strdown(str+18);
		if (!signal_emit(str, 1, server)) {
			g_warning("No one handled the abort of SASL mechanism %s",
				  conn->sasl_mechanism);
		}
		g_free(str);
	}
}

/*
 * This is the callback from g_timeout_add.
 */
static gboolean sasl_timeout_callback(IRC_SERVER_REC *server)
{
	/* The authentication timed out, we can't do much beside terminating it */
	sasl_abort(server);
	signal_emit("server sasl failure", 2, server, "The authentication timed out");

	return FALSE;
}

static void sasl_timeout_cancel(IRC_SERVER_REC *server)
{
	if (server->sasl_timeout != 0) {
		g_source_remove(server->sasl_timeout);
		server->sasl_timeout = 0;
	}
}

static void sasl_timeout_start(IRC_SERVER_REC *server)
{
	sasl_timeout_cancel(server);
	server->sasl_timeout = g_timeout_add_seconds(SASL_TIMEOUT, (GSourceFunc) sasl_timeout_callback,
						     server);
}

void sasl_abort(IRC_SERVER_REC *server)
{
	sasl_timeout_cancel(server);

	irc_send_cmd_now(server, "AUTHENTICATE *");
	cap_finish_negotiation(server);

	sasl_emit_abort_signal(server);
}

static void sasl_start(IRC_SERVER_REC *server, const char *data, const char *from)
{
	IRC_SERVER_CONNECT_REC *conn;

	conn = server->connrec;

	if (!g_strcmp0(conn->sasl_mechanism, "PLAIN")) {
		irc_send_cmd_now(server, "AUTHENTICATE PLAIN");
		sasl_timeout_start(server);
	} else if (!g_strcmp0(conn->sasl_mechanism, "external")) {
		irc_send_cmd_now(server, "AUTHENTICATE EXTERNAL");
		sasl_timeout_start(server);
	} else if (is_registered_mechanism(conn->sasl_mechanism)) {
		char *str;

		str = g_strconcat("server sasl init ", conn->sasl_mechanism, NULL);
		ascii_strdown(str+17);
		if (!signal_emit(str, 1, server)) {
			g_warning("Nothing handled initialization of SASL mechanism %s",
				  conn->sasl_mechanism);
		}
		g_free(str);

		str = g_strconcat("AUTHENTICATE ", conn->sasl_mechanism, NULL);
		irc_send_cmd_now(server, str);
		g_free(str);
		sasl_timeout_start(server);
	} else {
		g_warning("Unsupported SASL mechanism \"%s\" selected", conn->sasl_mechanism);
		sasl_abort(server);
	}
}

static void sasl_fail(IRC_SERVER_REC *server, const char *data, const char *from)
{
	char *params, *error;

	sasl_timeout_cancel(server);

	params = event_get_params(data, 2, NULL, &error);

	signal_emit("server sasl failure", 2, server, error);
	sasl_emit_abort_signal(server);

	/* Terminate the negotiation */
	cap_finish_negotiation(server);

	g_free(params);
}

static void sasl_already(IRC_SERVER_REC *server, const char *data, const char *from)
{
	sasl_timeout_cancel(server);

	signal_emit("server sasl success", 1, server);
	sasl_emit_abort_signal(server);

	/* We're already authenticated, do nothing */
	cap_finish_negotiation(server);
}

static void sasl_success(IRC_SERVER_REC *server, const char *data, const char *from)
{
	sasl_timeout_cancel(server);

	signal_emit("server sasl success", 1, server);

	/* The authentication succeeded, time to finish the CAP negotiation */
	cap_finish_negotiation(server);
}

static void sasl_send_step_if_complete(IRC_SERVER_REC *server, const char *enc_req)
{
	char *buffer;
	size_t enc_req_len;

	enc_req_len = strlen(enc_req);

	buffer = g_hash_table_lookup(sasl_buffers, server->tag);
	if (buffer != NULL) {
		if (!g_strcmp0("+", enc_req)) {
			enc_req = buffer;
		} else {
			enc_req = g_strconcat(buffer, enc_req, NULL);
		}
		g_hash_table_remove(sasl_buffers, server->tag);
	}

	if (enc_req_len == 400) {
		g_hash_table_insert(sasl_buffers, server->tag, g_strdup(enc_req));
	} else {
		gchar *output;
		GBytes *decoded;
		IRC_SERVER_CONNECT_REC *conn;

		if (!g_strcmp0("+", enc_req)) {
			decoded = g_bytes_new("", 0);
		} else {
			gsize dec_len;
			guchar *tmp;

			tmp = g_base64_decode(enc_req, &dec_len);
			decoded = g_bytes_new(tmp, dec_len);
		}

		conn = server->connrec;
		output = g_strconcat("server sasl step ", conn->sasl_mechanism, NULL);
		ascii_strdown(output+17);

		if (!signal_emit(output, 2, server, decoded)) {
			g_warning("No one can handle SASL mechanism: %s",
				  conn->sasl_mechanism);
		}
		g_free(output);
		g_bytes_unref(decoded);
	}

	g_free_not_null(buffer);
}

void sasl_send_response(IRC_SERVER_REC *server, GBytes *response)
{
	char *enc;
	const guchar *p;
	gsize len;
	size_t offset, enc_len;

	p = g_bytes_get_data(response, &len);
	enc = g_base64_encode(p, len);
	enc_len = strlen(enc);

	offset = 0;
	while (offset < enc_len) {
		irc_send_cmdv(server, "AUTHENTICATE %400s",
			      offset == enc_len ? "+" : (enc + offset));
		offset += 400;
	}
	g_free(enc);
}

static void sasl_step(IRC_SERVER_REC *server, const char *data, const char *from)
{
	IRC_SERVER_CONNECT_REC *conn;
	GString *req;

	conn = server->connrec;

	sasl_timeout_cancel(server);

	if (!g_strcmp0(conn->sasl_mechanism, "plain")) {
		/* At this point we assume that conn->sasl_{username, password} are non-NULL.
		 * The PLAIN mechanism expects a NULL-separated string composed by the authorization identity, the
		 * authentication identity and the password.
		 * The authorization identity field is explicitly set to the user provided username.
		 * The whole request is then encoded in base64. */
		GBytes *bytes;

		req = g_string_new(NULL);

		g_string_append(req, conn->sasl_username);
		g_string_append_c(req, '\0');
		g_string_append(req, conn->sasl_username);
		g_string_append_c(req, '\0');
		g_string_append(req, conn->sasl_password);

		bytes = g_bytes_new(req->str, req->len);
		sasl_send_response(server, bytes);
		g_string_free(req, TRUE);
	} else if (!g_strcmp0(conn->sasl_mechanism, "external")) {
		/* Empty response */
		irc_send_cmdv(server, "AUTHENTICATE +");
	} else {
		sasl_send_step_if_complete(server, data);
	}

	/* We expect a response within a reasonable time */
	sasl_timeout_start(server);
}

static void sasl_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server)) {
		return;
	}

	sasl_timeout_cancel(server);

	sasl_emit_abort_signal(server);
}

void sasl_init(void)
{
	sasl_buffers = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);

	signal_add_first("server cap ack sasl", (SIGNAL_FUNC) sasl_start);
	signal_add_first("event authenticate", (SIGNAL_FUNC) sasl_step);
	signal_add_first("event 903", (SIGNAL_FUNC) sasl_success);
	signal_add_first("event 902", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 904", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 905", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 906", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 907", (SIGNAL_FUNC) sasl_already);
	signal_add_first("server disconnected", (SIGNAL_FUNC) sasl_disconnected);
}

void sasl_deinit(void)
{
	g_hash_table_destroy(sasl_buffers);

	signal_remove("server cap ack sasl", (SIGNAL_FUNC) sasl_start);
	signal_remove("event authenticate", (SIGNAL_FUNC) sasl_step);
	signal_remove("event 903", (SIGNAL_FUNC) sasl_success);
	signal_remove("event 902", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 904", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 905", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 906", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 907", (SIGNAL_FUNC) sasl_already);
	signal_remove("server disconnected", (SIGNAL_FUNC) sasl_disconnected);
}
