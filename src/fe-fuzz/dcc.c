/*
 dcc.c : irssi DCC fuzzer

    Copyright (C) 2018 Joseph Bisch
    Copyright (C) 2025 irssi contributors

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

#include <irssi/src/irc/core/module.h>
#include <irssi/src/core/modules-load.h>
#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/core/core.h>
#include <irssi/src/fe-common/core/fe-common-core.h>
#include <irssi/src/core/args.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/rawlog.h>
#include <irssi/src/core/network-openssl.h>
#include <irssi/src/core/net-sendbuffer.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/fe-fuzz/null-logger.h>

/* irc-core.c */
void irc_core_init(void);
void irc_core_deinit(void);

/* irc-session.c */
void irc_session_init(void);
void irc_session_deinit(void);

/* fe-common-irc.c */
void fe_common_irc_init(void);
void fe_common_irc_deinit(void);

SERVER_REC *server;

void event_connected(IRC_SERVER_REC *server, const char *data, const char *from)
{
	char *params, *nick;

	g_return_if_fail(server != NULL);

	params = event_get_params(data, 1, &nick);

	if (g_strcmp0(server->nick, nick) != 0) {
		/* nick changed unexpectedly .. connected via proxy, etc. */
		g_free(server->nick);
		server->nick = g_strdup(nick);
	}

	/* set the server address */
	g_free(server->real_address);
	server->real_address = from == NULL ?
		g_strdup(server->connrec->address) : /* shouldn't happen.. */
		g_strdup(from);

	/* last welcome message found - commands can be sent to server now. */
	server->connected = 1;
	server->real_connect_time = time(NULL);

	/* let the queue send now that we are identified */
	g_get_current_time(&server->wait_cmd);

	if (server->connrec->usermode != NULL) {
		/* Send the user mode, before the autosendcmd.
		 * Do not pass this through cmd_mode because it
		 * is not known whether the resulting MODE message
		 * (if any) is the initial umode or a reply to this.
		 */
		irc_send_cmdv(server, "MODE %s %s", server->nick,
				server->connrec->usermode);
		g_free_not_null(server->wanted_usermode);
		server->wanted_usermode = g_strdup(server->connrec->usermode);
	}

	signal_emit("event connected", 1, server);
	g_free(params);
}

void irc_server_init_bare_minimum(IRC_SERVER_REC *server) {
	server->rawlog = rawlog_create();

	/* isupport is already created by server_init_connect, just populate it */
	g_hash_table_insert(server->isupport, g_strdup("CHANMODES"), g_strdup("beI,k,l,imnpst"));
	g_hash_table_insert(server->isupport, g_strdup("PREFIX"), g_strdup("(ohv)@%+"));
}

void test_server() {
	CHAT_PROTOCOL_REC *proto;
	SERVER_CONNECT_REC *conn;
	GIOChannel *handle = g_io_channel_unix_new(open("/dev/null", O_RDWR));
	g_io_channel_set_encoding(handle, NULL, NULL);
	g_io_channel_set_close_on_unref(handle, TRUE);

	proto = chat_protocol_find("IRC");
	conn = server_create_conn(proto->id, "localhost", 0, "", "", "user");
	server = proto->server_init_connect(conn);
	server->session_reconnect = TRUE;
	g_free(server->tag);
	server->tag = g_strdup("testserver");
	server->handle = net_sendbuffer_create(handle, 0);

	/* we skip some initialisations that would try to send data */
	irc_session_deinit();
	irc_irc_deinit();

	server_connect_finished(server);

	/* make up for the skipped session init */
	irc_server_init_bare_minimum(IRC_SERVER(server));

	irc_irc_init();
	irc_session_init();

	server_connect_unref(conn);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	g_log_set_null_logger();
#endif
	core_register_options();
	fe_common_core_register_options();
	/* no args */
	args_execute(0, NULL);
	core_preinit((*argv)[0]);
	core_init();
	irssi_ssl_init();
	irc_core_init();
	fe_common_core_init();
	fe_common_irc_init();
	signal_add("event 001", (SIGNAL_FUNC) event_connected);
	module_register("core", "fe-fuzz");
	rawlog_set_size(1);
	return 0;
}

/*
 * DCC fuzzer input format:
 * Byte 0: DCC type selector
 *   0 = DCC SEND
 *   1 = DCC CHAT
 *   2 = DCC RESUME
 *   3 = DCC ACCEPT
 *   4 = DCC GET (command parsing)
 *   5 = DCC CLOSE (command parsing)
 *   6+ = raw CTCP DCC message
 *
 * Remaining bytes: DCC message content (after "DCC <type> ")
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	gchar *copy;
	gchar *ctcp_line;
	gchar *irc_line;
	int dcc_type;
	int disconnected;

	if (size < 2) return 0;

	test_server();

	dcc_type = data[0] % 7;
	copy = g_strndup((const gchar *)data+1, size-1);

	/* Replace any NUL bytes with spaces to allow fuzzing of full data */
	for (size_t i = 0; i < size-1; i++) {
		if (copy[i] == '\0') copy[i] = ' ';
	}

	switch (dcc_type) {
	case 0: /* DCC SEND - file transfer offer */
		ctcp_line = g_strdup_printf("DCC SEND %s", copy);
		break;
	case 1: /* DCC CHAT - chat request */
		ctcp_line = g_strdup_printf("DCC CHAT %s", copy);
		break;
	case 2: /* DCC RESUME - resume file transfer */
		ctcp_line = g_strdup_printf("DCC RESUME %s", copy);
		break;
	case 3: /* DCC ACCEPT - accept resume */
		ctcp_line = g_strdup_printf("DCC ACCEPT %s", copy);
		break;
	case 4: /* DCC GET command parsing */
		/* Test the command parsing path via "dcc get" command */
		signal_emit("command dcc get", 3, copy, server, NULL);
		g_free(copy);
		goto cleanup;
	case 5: /* DCC CLOSE command parsing */
		/* Test the command parsing path via "dcc close" command */
		signal_emit("command dcc close", 3, copy, server, NULL);
		g_free(copy);
		goto cleanup;
	default: /* Raw CTCP DCC message */
		ctcp_line = g_strdup_printf("DCC %s", copy);
		break;
	}

	/* Emit the DCC CTCP message signal directly
	 * This is what happens when a CTCP message is received:
	 * server, data, nick, addr, target, chat */
	server_ref(server);
	signal_emit("ctcp msg dcc", 6, server, ctcp_line,
		    "fuzzernick", "fuzzer@host.example.com", "testnick", NULL);
	disconnected = server->disconnected;
	server_unref(server);

	g_free(ctcp_line);
	g_free(copy);

cleanup:
	if (server->disconnected) {
		test_server();
	} else {
		server_disconnect(server);
	}
	return 0;
}
