#include "module.h"
#include "misc.h"
#include "settings.h"

#include "irc-cap.h"
#include "irc-servers.h"
#include "sasl.h"

#define SASL_TIMEOUT (20 * 1000) // ms

static gboolean sasl_timeout (IRC_SERVER_REC *server)
{
	/* The authentication timed out, we can't do much beside terminating it */
	g_critical("The authentication timed out, try increasing the timeout and check your connection "
	           "to the network.");
	irc_send_cmd_now(server, "AUTHENTICATE *");
	cap_finish_negotiation(server);

	server->sasl_timeout = -1;

	return FALSE;
}

static void sasl_start (IRC_SERVER_REC *server, const char *data, const char *from)
{
	IRC_SERVER_CONNECT_REC *conn;

	conn = server->connrec;

	switch (conn->sasl_mechanism) {
		case SASL_MECHANISM_PLAIN:
			irc_send_cmd_now(server, "AUTHENTICATE PLAIN");
			break;

		case SASL_MECHANISM_EXTERNAL:
			irc_send_cmd_now(server, "AUTHENTICATE EXTERNAL");
			break;
	}
	server->sasl_timeout = g_timeout_add(SASL_TIMEOUT, (GSourceFunc) sasl_timeout, server);
}

static void sasl_fail (IRC_SERVER_REC *server, const char *data, const char *from)
{
	char *params, *error;

	/* Stop any pending timeout, if any */
	if (server->sasl_timeout != -1) {
		g_source_remove(server->sasl_timeout);
		server->sasl_timeout = -1;
	}

	params = event_get_params(data, 2, NULL, &error);

	g_critical("Authentication failed with reason \"%s\"", error);

	/* Terminate the negotiation */
	cap_finish_negotiation(server);

	g_free(params);
}

static void sasl_already (IRC_SERVER_REC *server, const char *data, const char *from)
{
	if (server->sasl_timeout != -1) {
		g_source_remove(server->sasl_timeout);
		server->sasl_timeout = -1;
	}

	/* We're already authenticated, do nothing */
	cap_finish_negotiation(server);
}

static void sasl_success (IRC_SERVER_REC *server, const char *data, const char *from)
{
	if (server->sasl_timeout != -1) {
		g_source_remove(server->sasl_timeout);
		server->sasl_timeout = -1;
	}

	/* The authentication succeeded, time to finish the CAP negotiation */
	g_warning("SASL authentication succeeded");
	cap_finish_negotiation(server);
}

static void sasl_step (IRC_SERVER_REC *server, const char *data, const char *from)
{
	IRC_SERVER_CONNECT_REC *conn;
	GString *req;
	char *enc_req;

	conn = server->connrec;

	/* Stop the timer */
	if (server->sasl_timeout != -1) {
		g_source_remove(server->sasl_timeout);
		server->sasl_timeout = -1;
	}

	switch (conn->sasl_mechanism) {
		case SASL_MECHANISM_PLAIN:
			/* At this point we assume that conn->sasl_{username, password} are non-NULL.
			 * The PLAIN mechanism expects a NULL-separated string composed by the authorization identity, the
			 * authentication identity and the password.
			 * The authorization identity field is explicitly set to the user provided username.
			 * The whole request is then encoded in base64. */

			req = g_string_new(NULL);

			g_string_append(req, conn->sasl_username);
			g_string_append_c(req, '\0');
			g_string_append(req, conn->sasl_username);
			g_string_append_c(req, '\0');
			g_string_append(req, conn->sasl_password);

			enc_req = g_base64_encode((const guchar *)req->str, req->len);

			irc_send_cmdv(server, "AUTHENTICATE %s", enc_req);

			g_free(enc_req);
			g_string_free(req, TRUE);
			break;

		case SASL_MECHANISM_EXTERNAL:
			/* Empty response */
			irc_send_cmdv(server, "+");
			break;
	}

	/* We expect a response within a reasonable time */
	server->sasl_timeout = g_timeout_add(SASL_TIMEOUT, (GSourceFunc) sasl_timeout, server);
}

void sasl_init(void)
{
	signal_add_first("server cap ack sasl", (SIGNAL_FUNC) sasl_start);
	signal_add_first("event authenticate", (SIGNAL_FUNC) sasl_step);
	signal_add_first("event 903", (SIGNAL_FUNC) sasl_success);
	signal_add_first("event 902", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 904", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 905", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 906", (SIGNAL_FUNC) sasl_fail);
	signal_add_first("event 907", (SIGNAL_FUNC) sasl_already);
	signal_add_first("event 908", (SIGNAL_FUNC) sasl_fail);
}

void sasl_deinit(void)
{
	signal_remove("server cap ack sasl", (SIGNAL_FUNC) sasl_start);
	signal_remove("event authenticate", (SIGNAL_FUNC) sasl_step);
	signal_remove("event 903", (SIGNAL_FUNC) sasl_success);
	signal_remove("event 902", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 904", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 905", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 906", (SIGNAL_FUNC) sasl_fail);
	signal_remove("event 907", (SIGNAL_FUNC) sasl_already);
	signal_remove("event 908", (SIGNAL_FUNC) sasl_fail);
}
