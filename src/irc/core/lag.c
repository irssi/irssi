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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"

#include "irc-servers.h"
#include "servers-redirect.h"

typedef struct {
	IRC_SERVER_REC *server;
	GTimeVal time;
} LAG_REC;

static gint timeout_tag;
static GSList *lags;

static LAG_REC *lag_find(IRC_SERVER_REC *server)
{
	GSList *tmp;

	for (tmp = lags; tmp != NULL; tmp = tmp->next) {
		LAG_REC *lag = tmp->data;

		if (lag->server == server)
			return lag;
	}

	return NULL;
}

static void lag_free(LAG_REC *rec)
{
	lags = g_slist_remove(lags, rec);
	g_free(rec);
}

static void lag_send(LAG_REC *lag)
{
	IRC_SERVER_REC *server;

	g_get_current_time(&lag->time);

        server = lag->server;
	server->lag_sent = server->lag_last_check = time(NULL);
	server_redirect_event(server, "ping", 1, NULL, FALSE,
			      "lag ping error",
                              "event pong", "lag pong", NULL);
	irc_send_cmdv(server, "PING %s", server->real_address);
}

static void lag_get(IRC_SERVER_REC *server)
{
	LAG_REC *lag;

	g_return_if_fail(server != NULL);

	/* nick changes may fail this check, so we should never do this
	   while there's nick change request waiting for reply in server.. */
	lag = g_new0(LAG_REC, 1);
	lags = g_slist_append(lags, lag);
	lag->server = server;

        lag_send(lag);
}

/* we didn't receive PONG for some reason .. try again */
static void lag_ping_error(IRC_SERVER_REC *server)
{
	LAG_REC *lag;

	lag = lag_find(server);
        if (lag != NULL)
		lag_send(lag);
}

static void lag_event_pong(IRC_SERVER_REC *server, const char *data,
			   const char *nick, const char *addr)
{
	GTimeVal now;
	LAG_REC *lag;

	g_return_if_fail(data != NULL);

	lag = lag_find(server);
	if (lag == NULL) {
		/* not expecting lag reply.. */
		return;
	}

	server->lag_sent = 0;

	g_get_current_time(&now);
	server->lag = (int) get_timeval_diff(&now, &lag->time);
	signal_emit("server lag", 1, server);

	lag_free(lag);
}

static int sig_check_lag(void)
{
	GSList *tmp, *next;
	time_t now;
	int lag_check_time, max_lag;

	lag_check_time = settings_get_int("lag_check_time");
	max_lag = settings_get_int("lag_max_before_disconnect");

	if (lag_check_time <= 0)
		return 1;

	now = time(NULL);
	for (tmp = servers; tmp != NULL; tmp = next) {
		IRC_SERVER_REC *rec = tmp->data;

		next = tmp->next;
		if (!IS_IRC_SERVER(rec))
			continue;

		if (rec->lag_sent != 0) {
			/* waiting for lag reply */
			if (max_lag > 1 && now-rec->lag_sent > max_lag) {
				/* too much lag, disconnect */
				signal_emit("server lag disconnect", 1, rec);
				rec->connection_lost = TRUE;
				server_disconnect((SERVER_REC *) rec);
			}
		} else if (rec->lag_last_check+lag_check_time < now &&
			 rec->cmdcount == 0 && rec->connected) {
			/* no commands in buffer - get the lag */
			lag_get(rec);
		}
	}

	return 1;
}

void lag_init(void)
{
	settings_add_int("misc", "lag_check_time", 30);
	settings_add_int("misc", "lag_max_before_disconnect", 300);

	lags = NULL;
	timeout_tag = g_timeout_add(1000, (GSourceFunc) sig_check_lag, NULL);
	signal_add_first("lag pong", (SIGNAL_FUNC) lag_event_pong);
        signal_add("lag ping error", (SIGNAL_FUNC) lag_ping_error);
}

void lag_deinit(void)
{
	g_source_remove(timeout_tag);
	while (lags != NULL)
		lag_free(lags->data);
	signal_remove("lag pong", (SIGNAL_FUNC) lag_event_pong);
        signal_remove("lag ping error", (SIGNAL_FUNC) lag_ping_error);
}
