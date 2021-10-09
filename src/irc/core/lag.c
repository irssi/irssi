/*
 lag.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/servers-redirect.h>

static int timeout_tag;

static void lag_get(IRC_SERVER_REC *server)
{
	server->lag_sent = g_get_real_time();
	server->lag_last_check = time(NULL);

	server_redirect_event(server, "ping", 1, NULL, FALSE,
			      "lag ping error",
                              "event pong", "lag pong", NULL);
	irc_send_cmdv(server, "PING %s", server->real_address);
}

/* we didn't receive PONG for some reason .. try again */
static void lag_ping_error(IRC_SERVER_REC *server)
{
	lag_get(server);
}

static void lag_event_pong(IRC_SERVER_REC *server, const char *data,
			   const char *nick, const char *addr)
{
	gint64 now;

	g_return_if_fail(data != NULL);

	if (server->lag_sent == 0) {
		/* not expecting lag reply.. */
		return;
	}

	now = g_get_real_time();
	server->lag = (now - server->lag_sent) / G_TIME_SPAN_MILLISECOND;
	server->lag_sent = 0;

	signal_emit("server lag", 1, server);
}

static void sig_unknown_command(IRC_SERVER_REC *server, const char *data)
{
	char *params, *cmd;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &cmd);
	if (g_ascii_strcasecmp(cmd, "PING") == 0) {
		/* some servers have disabled PING command, don't bother
		   trying alternative methods to detect lag with these
		   servers. */
		server->disable_lag = TRUE;
		server->lag_sent = 0;
		server->lag = 0;
	}
	g_free(params);
}

static int sig_check_lag(void)
{
	GSList *tmp, *next;
	time_t now;
	int lag_check_time, max_lag;

	lag_check_time = settings_get_time("lag_check_time")/1000;
	max_lag = settings_get_time("lag_max_before_disconnect")/1000;

	if (lag_check_time <= 0)
		return 1;

	now = time(NULL);
	for (tmp = servers; tmp != NULL; tmp = next) {
		IRC_SERVER_REC *rec = tmp->data;

		next = tmp->next;
		if (!IS_IRC_SERVER(rec) || rec->disable_lag)
			continue;

		if (rec->lag_sent != 0) {
			/* waiting for lag reply */
			if (max_lag > 1 && now - (rec->lag_sent / G_TIME_SPAN_SECOND) > max_lag) {
				/* too much lag, disconnect */
				signal_emit("server lag disconnect", 1, rec);
				rec->connection_lost = TRUE;
				server_disconnect((SERVER_REC *) rec);
			}
		} else if (rec->lag_last_check + lag_check_time < now && rec->cmdcount == 0 &&
		           rec->connected) {
			/* no commands in buffer - get the lag */
			lag_get(rec);
		}
	}

	return 1;
}

void lag_init(void)
{
	settings_add_time("misc", "lag_check_time", "1min");
	settings_add_time("misc", "lag_max_before_disconnect", "5min");

	timeout_tag = g_timeout_add(1000, (GSourceFunc) sig_check_lag, NULL);
	signal_add_first("lag pong", (SIGNAL_FUNC) lag_event_pong);
        signal_add("lag ping error", (SIGNAL_FUNC) lag_ping_error);
        signal_add("event 421", (SIGNAL_FUNC) sig_unknown_command);
}

void lag_deinit(void)
{
	g_source_remove(timeout_tag);
	signal_remove("lag pong", (SIGNAL_FUNC) lag_event_pong);
        signal_remove("lag ping error", (SIGNAL_FUNC) lag_ping_error);
        signal_remove("event 421", (SIGNAL_FUNC) sig_unknown_command);
}
