/*
 server-idle.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/servers-idle.h>
#include <irssi/src/irc/core/servers-redirect.h>

typedef struct {
	char *cmd;
	char *arg;
	int tag;

	char *redirect_cmd;
        int count;
	int remote;
	char *failure_signal;
	GSList *redirects;
} SERVER_IDLE_REC;

static int idle_tag, idlepos;

/* Add new idle command to queue */
static SERVER_IDLE_REC *
server_idle_create(const char *cmd, const char *redirect_cmd, int count,
		   const char *arg, int remote, const char *failure_signal,
		   va_list va)
{
	SERVER_IDLE_REC *rec;
	const char *event, *signal;

	g_return_val_if_fail(cmd != NULL, FALSE);

	rec = g_new0(SERVER_IDLE_REC, 1);
	rec->cmd = g_strdup(cmd);
	rec->arg = g_strdup(arg);
	rec->tag = ++idlepos;

        rec->redirect_cmd = g_strdup(redirect_cmd);
	rec->count = count;
	rec->remote = remote;
        rec->failure_signal = g_strdup(failure_signal);

	while ((event = va_arg(va, const char *)) != NULL) {
		signal = va_arg(va, const char *);
		if (signal == NULL) {
			g_warning("server_idle_create(%s): "
				  "signal not specified for event",
				  redirect_cmd);
			break;
		}

		rec->redirects =
			g_slist_append(rec->redirects, g_strdup(event));
		rec->redirects =
			g_slist_append(rec->redirects, g_strdup(signal));
	}

	return rec;
}

static SERVER_IDLE_REC *server_idle_find_rec(IRC_SERVER_REC *server, int tag)
{
	GSList *tmp;

	g_return_val_if_fail(server != NULL, FALSE);

	for (tmp = server->idles; tmp != NULL; tmp = tmp->next) {
		SERVER_IDLE_REC *rec = tmp->data;

		if (rec->tag == tag)
			return rec;
	}

	return NULL;
}

/* Add new idle command to queue */
int server_idle_add_redir(IRC_SERVER_REC *server, const char *cmd,
			  const char *redirect_cmd, int count, const char *arg,
			  int remote, const char *failure_signal, ...)
{
	va_list va;
	SERVER_IDLE_REC *rec;

	g_return_val_if_fail(server != NULL, -1);

	va_start(va, failure_signal);
	rec = server_idle_create(cmd, redirect_cmd, count, arg, remote,
				 failure_signal, va);
	server->idles = g_slist_append(server->idles, rec);
	va_end(va);

	return rec->tag;
}

/* Add new idle command to first of queue */
int server_idle_add_first_redir(IRC_SERVER_REC *server, const char *cmd,
				const char *redirect_cmd, int count,
				const char *arg, int remote,
				const char *failure_signal, ...)
{
	va_list va;
	SERVER_IDLE_REC *rec;

	g_return_val_if_fail(server != NULL, -1);

	va_start(va, failure_signal);
	rec = server_idle_create(cmd, redirect_cmd, count, arg, remote,
				 failure_signal, va);
	server->idles = g_slist_prepend(server->idles, rec);
	va_end(va);

	return rec->tag;
}

/* Add new idle command to specified position of queue */
int server_idle_insert_redir(IRC_SERVER_REC *server, const char *cmd, int tag,
			     const char *redirect_cmd, int count,
			     const char *arg, int remote,
			     const char *failure_signal, ...)
{
	va_list va;
	SERVER_IDLE_REC *rec;
	int pos;

	g_return_val_if_fail(server != NULL, -1);

	va_start(va, failure_signal);

	/* find the position of tag in idle list */
	rec = server_idle_find_rec(server, tag);
	pos = g_slist_index(server->idles, rec);

	rec = server_idle_create(cmd, redirect_cmd, count, arg, remote,
				 failure_signal, va);
        server->idles = pos < 0 ?
		g_slist_append(server->idles, rec) :
		g_slist_insert(server->idles, rec, pos);
	va_end(va);

	return rec->tag;
}

static void server_idle_destroy(IRC_SERVER_REC *server, SERVER_IDLE_REC *rec)
{
	g_return_if_fail(server != NULL);

	server->idles = g_slist_remove(server->idles, rec);

        g_slist_foreach(rec->redirects, (GFunc) g_free, NULL);
	g_slist_free(rec->redirects);

	g_free_not_null(rec->arg);
        g_free_not_null(rec->redirect_cmd);
        g_free_not_null(rec->failure_signal);
	g_free(rec->cmd);
	g_free(rec);
}

/* Check if record is still in queue */
int server_idle_find(IRC_SERVER_REC *server, int tag)
{
	return server_idle_find_rec(server, tag) != NULL;
}

/* Remove record from idle queue */
int server_idle_remove(IRC_SERVER_REC *server, int tag)
{
	SERVER_IDLE_REC *rec;

	g_return_val_if_fail(server != NULL, FALSE);

	rec = server_idle_find_rec(server, tag);
	if (rec == NULL)
		return FALSE;

	server_idle_destroy(server, rec);
	return TRUE;
}

/* Execute next idle command */
static void server_idle_next(IRC_SERVER_REC *server)
{
	SERVER_IDLE_REC *rec;

	g_return_if_fail(server != NULL);

	if (server->idles == NULL)
		return;
	rec = server->idles->data;

	/* Send command */
	if (rec->redirect_cmd != NULL) {
		server_redirect_event_list(server, rec->redirect_cmd,
					   rec->count, rec->arg,
					   rec->remote, rec->failure_signal,
					   rec->redirects);
	}
	irc_send_cmd(server, rec->cmd);

	server_idle_destroy(server, rec);
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	if (!IS_IRC_SERVER(server))
		return;

	while (server->idles != NULL)
		server_idle_destroy(server, server->idles->data);
}

static int sig_idle_timeout(void)
{
	GSList *tmp;

	/* Scan through every server */
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		if (IS_IRC_SERVER(rec) &&
		    rec->idles != NULL && rec->cmdcount == 0) {
			/* We're idling and we have idle commands to run! */
			server_idle_next(rec);
		}
	}
	return 1;
}

void servers_idle_init(void)
{
	idlepos = 0;
	idle_tag = g_timeout_add(1000, (GSourceFunc) sig_idle_timeout, NULL);

	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}

void servers_idle_deinit(void)
{
	g_source_remove(idle_tag);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}
