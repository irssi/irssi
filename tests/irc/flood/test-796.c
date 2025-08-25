/*
 test-796.c : irssi

    Copyright (C) 2017 The Irssi project.

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

#include <irssi/src/common.h>
#include <irssi/src/core/args.h>
#include <irssi/src/core/core.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/servers-setup.h>

#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-common/core/fe-common-core.h>

#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>

/* flood.c */
void irc_flood_init(void);
void irc_flood_deinit(void);

/* irc-core.c */
void irc_core_init(void);
void irc_core_deinit(void);

/* irc-session.c */
void irc_session_init(void);
void irc_session_deinit(void);

/* fe-common-irc.c */
void fe_common_irc_init(void);
void fe_common_irc_deinit(void);

typedef struct {
} ServerDestroyFloodData;

#define MODULE_NAME "tests"

static void cmd_echo(const char *data, void *server, WI_ITEM_REC *item)
{
	g_test_message("echo: [server=%p,item=%p] %s", server, item, data);
}

static void sig_public(SERVER_REC *server, const char *msg, const char *nick, const char *address, const char *target)
{
	signal_emit("send command", 3, "/eval echo $tag", server, NULL);
}

static void print_disconnect(SERVER_REC *server)
{
	g_test_message("server %p was disconnected", server);
}

static void print_destroyed(SERVER_REC *server)
{
	g_test_message("server %p was destroyed", server);
}

static void server_destroy_flood_set_up(ServerDestroyFloodData *fixture, const void *data)
{
	args_execute(0, NULL);
	core_init();
	irc_core_init();
	irc_flood_init();
	fe_common_core_init();
	fe_common_irc_init();
	signal_emit("irssi init finished", 0);
	command_bind("echo", NULL, (SIGNAL_FUNC) cmd_echo);
	signal_add("message public", (SIGNAL_FUNC) sig_public);
	signal_add("server destroyed", (SIGNAL_FUNC) print_destroyed);
	signal_add_first("server disconnected", (SIGNAL_FUNC) print_disconnect);
}

static void server_destroy_flood_tear_down(ServerDestroyFloodData *fixture, const void *data)
{
	signal_remove("server disconnected", (SIGNAL_FUNC) print_disconnect);
	signal_remove("server destroyed", (SIGNAL_FUNC) print_destroyed);
	signal_remove("message public", (SIGNAL_FUNC) sig_public);
	command_unbind("echo", (SIGNAL_FUNC) cmd_echo);
	fe_common_irc_deinit();
	fe_common_core_deinit();
	irc_flood_deinit();
	irc_core_deinit();
	core_deinit();
}

static void irc_server_init_bare_minimum(IRC_SERVER_REC *server)
{
	server->isupport = g_hash_table_new((GHashFunc) i_istr_hash, (GCompareFunc) i_istr_equal);

	/* set the standards */
	g_hash_table_insert(server->isupport, g_strdup("CHANMODES"), g_strdup("beI,k,l,imnpst"));
	g_hash_table_insert(server->isupport, g_strdup("PREFIX"), g_strdup("(ohv)@%+"));
}

static void test_server_destroy_flood(ServerDestroyFloodData *fixture, const void *data)
{
	SERVER_REC *server; /* = g_new0(IRC_SERVER_REC, 1); */
	CHAT_PROTOCOL_REC *proto;
	SERVER_CONNECT_REC *conn;
	GLogLevelFlags loglev;

	g_test_bug("796");

	/* for the purpose of this exercise, we are ignoring the
	   errors of g_hash_table_lookup failure */
	loglev = g_log_set_always_fatal(G_LOG_FATAL_MASK);

	proto = chat_protocol_find("IRC");
	conn = server_create_conn(proto->id, "localhost", 0, "", "", "user");
	server = proto->server_init_connect(conn);
	server->session_reconnect = TRUE;
	server->tag = g_strdup("testserver");

	g_test_message("created server: %p", server);

	/* we skip some initialisations that would try to send data */
	/* irc_servers_deinit(); */
	irc_session_deinit();
	irc_irc_deinit();


	server_connect_finished(server);

	/* make up for the skipped session init */
	irc_server_init_bare_minimum(IRC_SERVER(server));

	irc_irc_init();
	irc_session_init();
	/* irc_servers_init(); */

	/* simulate failing irc_server_send_data() */
	server->connection_lost = TRUE;

	/*
	chat_completion_deinit();
	fe_messages_deinit();
	irc_notifylist_deinit();
	*/

	server_ref(server);
	signal_emit("event privmsg", 4, server, "#someroom :test message", "nick", "user@host");
	server_unref(server);

	g_log_set_always_fatal(loglev);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("https://github.com/irssi/irssi/issues/");

	g_test_add("/test/server_destroy_flood", ServerDestroyFloodData, NULL,
		   server_destroy_flood_set_up, test_server_destroy_flood,
		   server_destroy_flood_tear_down);

#if GLIB_CHECK_VERSION(2,38,0)
	g_test_set_nonfatal_assertions();
#endif

	core_preinit(*argv);
	irssi_gui = IRSSI_GUI_NONE;

	return g_test_run();
}
