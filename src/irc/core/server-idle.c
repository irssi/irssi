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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"

#include "irc-servers.h"
#include "server-idle.h"
#include "servers-redirect.h"

typedef struct {
	char *event;
	char *signal;
	int argpos;
} REDIRECT_IDLE_REC;

typedef struct {
	char *cmd;
	char *arg;
	int tag;

	int last;
	GSList *redirects;
} SERVER_IDLE_REC;

static int idle_tag, idlepos;

/* Add new idle command to queue */
static SERVER_IDLE_REC *server_idle_create(const char *cmd, const char *arg, int last, va_list args)
{
	REDIRECT_IDLE_REC *rrec;
	SERVER_IDLE_REC *rec;
	char *event;

	g_return_val_if_fail(cmd != NULL, FALSE);

	rec = g_new0(SERVER_IDLE_REC, 1);

	rec->tag = ++idlepos;
	rec->arg = arg == NULL ? NULL : g_strdup(arg);
	rec->cmd = g_strdup(cmd);
	rec->last = last;

	while ((event = va_arg(args, char *)) != NULL) {
		rrec = g_new(REDIRECT_IDLE_REC, 1);
		rec->redirects = g_slist_append(rec->redirects, rrec);

		rrec->event = g_strdup(event);
		rrec->signal = g_strdup(va_arg(args, char *));
		rrec->argpos = va_arg(args, int);
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
int server_idle_add(IRC_SERVER_REC *server, const char *cmd, const char *arg, int last, ...)
{
	va_list args;
	SERVER_IDLE_REC *rec;

	g_return_val_if_fail(server != NULL, -1);

	va_start(args, last);
	rec = server_idle_create(cmd, arg, last, args);
	server->idles = g_slist_append(server->idles, rec);
	va_end(args);

	return rec->tag;
}

/* Add new idle command to first of queue */
int server_idle_add_first(IRC_SERVER_REC *server, const char *cmd, const char *arg, int last, ...)
{
	va_list args;
	SERVER_IDLE_REC *rec;

	g_return_val_if_fail(server != NULL, -1);

	va_start(args, last);
	rec = server_idle_create(cmd, arg, last, args);
	server->idles = g_slist_prepend(server->idles, rec);
	va_end(args);

	return rec->tag;
}

/* Add new idle command to specified position of queue */
int server_idle_insert(IRC_SERVER_REC *server, const char *cmd, const char *arg, int tag, int last, ...)
{
	va_list args;
	SERVER_IDLE_REC *rec;
	int pos;

	g_return_val_if_fail(server != NULL, -1);

	va_start(args, last);

	/* find the position of tag in idle list */
	rec = server_idle_find_rec(server, tag);
	pos = g_slist_index(server->idles, rec);

	rec = server_idle_create(cmd, arg, last, args);
        server->idles = pos < 0 ?
		g_slist_append(server->idles, rec) :
		g_slist_insert(server->idles, rec, pos);
	va_end(args);
	return rec->tag;
}

static void server_idle_destroy(IRC_SERVER_REC *server, SERVER_IDLE_REC *rec)
{
	GSList *tmp;

	g_return_if_fail(server != NULL);

	server->idles = g_slist_remove(server->idles, rec);

	for (tmp = rec->redirects; tmp != NULL; tmp = tmp->next) {
		REDIRECT_IDLE_REC *rec = tmp->data;

		g_free(rec->event);
		g_free(rec->signal);
		g_free(rec);
	}
	g_slist_free(rec->redirects);

	g_free_not_null(rec->arg);
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
	GSList *tmp;
	int group;

	g_return_if_fail(server != NULL);

	if (server->idles == NULL) return;
	rec = server->idles->data;

	/* Send command */
	irc_send_cmd(server, rec->cmd);

	/* Add server redirections */
	group = 0;
	for (tmp = rec->redirects; tmp != NULL; tmp = tmp->next) {
		REDIRECT_IDLE_REC *rrec = tmp->data;

		group = server_redirect_single_event((SERVER_REC *) server, rec->arg, rec->last > 0,
						     group, rrec->event, rrec->signal, rrec->argpos);
		if (rec->last > 0) rec->last--;
	}

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
