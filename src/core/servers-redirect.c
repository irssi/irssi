/*
 server-redirect.c : irssi

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
#include "misc.h"

#include "servers.h"
#include "servers-redirect.h"

static int redirect_group;

static void server_eventtable_destroy(char *key, GSList *value)
{
	GSList *tmp;

	g_free(key);

	for (tmp = value; tmp != NULL; tmp = tmp->next) {
		REDIRECT_REC *rec = tmp->data;

		g_free_not_null(rec->arg);
		g_free(rec->name);
		g_free(rec);
	}
	g_slist_free(value);
}

static void server_eventgrouptable_destroy(gpointer key, GSList *value)
{
	g_slist_foreach(value, (GFunc) g_free, NULL);
	g_slist_free(value);
}

static void server_cmdtable_destroy(char *key, REDIRECT_CMD_REC *value)
{
	g_free(key);

	g_slist_foreach(value->events, (GFunc) g_free, NULL);
	g_slist_free(value->events);
	g_free(value);
}

static void sig_disconnected(SERVER_REC *server)
{
	g_return_if_fail(IS_SERVER(server));

	if (server->eventtable != NULL) {
		g_hash_table_foreach(server->eventtable,
				     (GHFunc) server_eventtable_destroy, NULL);
		g_hash_table_destroy(server->eventtable);
	}

	g_hash_table_foreach(server->eventgrouptable,
			     (GHFunc) server_eventgrouptable_destroy, NULL);
	g_hash_table_destroy(server->eventgrouptable);

	if (server->cmdtable != NULL) {
		g_hash_table_foreach(server->cmdtable,
				     (GHFunc) server_cmdtable_destroy, NULL);
		g_hash_table_destroy(server->cmdtable);
	}
}

void server_redirect_initv(SERVER_REC *server, const char *command,
			   int last, GSList *list)
{
	REDIRECT_CMD_REC *rec;

	g_return_if_fail(IS_SERVER(server));
	g_return_if_fail(command != NULL);
	g_return_if_fail(last > 0);

	if (g_hash_table_lookup(server->cmdtable, command) != NULL) {
		/* already in hash table. list of events SHOULD be the same. */
		g_slist_foreach(list, (GFunc) g_free, NULL);
		g_slist_free(list);
		return;
	}

	rec = g_new(REDIRECT_CMD_REC, 1);
	rec->last = last;
	rec->events = list;
	g_hash_table_insert(server->cmdtable, g_strdup(command), rec);
}

void server_redirect_init(SERVER_REC *server, const char *command,
			  int last, ...)
{
	va_list args;
	GSList *list;
	char *event;

	va_start(args, last);
	list = NULL;
	while ((event = va_arg(args, gchar *)) != NULL)
		list = g_slist_append(list, g_strdup(event));
	va_end(args);

	server_redirect_initv(server, command, last, list);
}

int server_redirect_single_event(SERVER_REC *server, const char *arg,
				 int last, int group, const char *event,
				 const char *signal, int argpos)
{
	REDIRECT_REC *rec;
	GSList *list, *grouplist;
	char *origkey;

	g_return_val_if_fail(IS_SERVER(server), 0);
	g_return_val_if_fail(event != NULL, 0);
	g_return_val_if_fail(signal != NULL, 0);
	g_return_val_if_fail(arg != NULL || argpos == -1, 0);

	if (group == 0) group = ++redirect_group;

	rec = g_new0(REDIRECT_REC, 1);
	rec->arg = arg == NULL ? NULL : g_strdup(arg);
	rec->argpos = argpos;
	rec->name = g_strdup(signal);
	rec->group = group;
	rec->last = last;

	if (g_hash_table_lookup_extended(server->eventtable, event,
					 (gpointer *) &origkey,
					 (gpointer *) &list)) {
		g_hash_table_remove(server->eventtable, origkey);
	} else {
		list = NULL;
		origkey = g_strdup(event);
	}

	grouplist = g_hash_table_lookup(server->eventgrouptable,
					GINT_TO_POINTER(group));
	if (grouplist != NULL) {
		g_hash_table_remove(server->eventgrouptable,
				    GINT_TO_POINTER(group));
	}

	list = g_slist_append(list, rec);
	grouplist = g_slist_append(grouplist, g_strdup(event));

	g_hash_table_insert(server->eventtable, origkey, list);
	g_hash_table_insert(server->eventgrouptable,
			    GINT_TO_POINTER(group), grouplist);

	return group;
}

void server_redirect_event(SERVER_REC *server, const char *arg, int last, ...)
{
	va_list args;
	char *event, *signal;
	int argpos, group;

	g_return_if_fail(IS_SERVER(server));

	va_start(args, last);

	group = 0;
	while ((event = va_arg(args, gchar *)) != NULL) {
		signal = va_arg(args, gchar *);
		argpos = va_arg(args, gint);

		group = server_redirect_single_event(server, arg, last > 0,
						     group, event, signal,
						     argpos);
		last--;
	}

	va_end(args);
}

void server_redirect_default(SERVER_REC *server, const char *command)
{
	REDIRECT_CMD_REC *cmdrec;
	REDIRECT_REC *rec;
	GSList *events, *list, *grouplist;
	char *event, *origkey;
	int last;

	g_return_if_fail(IS_SERVER(server));
	g_return_if_fail(command != NULL);

	if (server->cmdtable == NULL)
		return; /* not connected yet */

	cmdrec = g_hash_table_lookup(server->cmdtable, command);
	if (cmdrec == NULL) return;

	/* add all events used by command to eventtable and eventgrouptable */
	redirect_group++; grouplist = NULL; last = cmdrec->last;
	for (events = cmdrec->events; events != NULL; events = events->next) {
		event = events->data;

		if (g_hash_table_lookup_extended(server->eventtable, event,
						 (gpointer *) &origkey,
						 (gpointer *) &list)) {
			g_hash_table_remove(server->eventtable, origkey);
		} else {
			list = NULL;
			origkey = g_strdup(event);
		}

		rec = g_new0(REDIRECT_REC, 1);
		rec->argpos = -1;
		rec->name = g_strdup(event);
		rec->group = redirect_group;
		rec->last = last > 0;

		grouplist = g_slist_append(grouplist, g_strdup(event));
		list = g_slist_append(list, rec);
		g_hash_table_insert(server->eventtable, origkey, list);

		last--;
	}

	g_hash_table_insert(server->eventgrouptable,
			    GINT_TO_POINTER(redirect_group), grouplist);
}

void server_redirect_remove_next(SERVER_REC *server, const char *event,
				 GSList *item)
{
	REDIRECT_REC *rec;
	GSList *grouplist, *list, *events, *tmp;
	char *origkey;
	int group;

	g_return_if_fail(IS_SERVER(server));
	g_return_if_fail(event != NULL);

	if (!g_hash_table_lookup_extended(server->eventtable, event,
					  (gpointer *) &origkey,
					  (gpointer *) &list))
		return;

	rec = item == NULL ? list->data : item->data;
	if (!rec->last) {
		/* this wasn't last expected event */
		return;
	}
	group = rec->group;

	/* get list of events from this group */
	grouplist = g_hash_table_lookup(server->eventgrouptable,
					GINT_TO_POINTER(group));

	/* remove all of them */
	for (list = grouplist; list != NULL; list = list->next) {
		char *event = list->data;

		if (!g_hash_table_lookup_extended(server->eventtable, event,
						  (gpointer *) &origkey,
						  (gpointer *) &events)) {
			g_warning("server_redirect_remove_next() : "
				  "event in eventgrouptable but not in "
				  "eventtable");
			continue;
		}

		/* remove the right group */
		for (tmp = events; tmp != NULL; tmp = tmp->next) {
			rec = tmp->data;

			if (rec->group == group)
				break;
		}

		if (rec == NULL) {
			g_warning("server_redirect_remove_next() : "
				  "event in eventgrouptable but not in "
				  "eventtable (group)");
			continue;
		}

		g_free(event);

		events = g_slist_remove(events, rec);
		g_free_not_null(rec->arg);
		g_free(rec->name);
		g_free(rec);

		/* update hash table */
		g_hash_table_remove(server->eventtable, origkey);
		if (events == NULL)
			g_free(origkey);
		else {
			g_hash_table_insert(server->eventtable,
					    origkey, events);
		}
	}

	g_hash_table_remove(server->eventgrouptable, GINT_TO_POINTER(group));
	g_slist_free(grouplist);
}

GSList *server_redirect_getqueue(SERVER_REC *server, const char *event,
				 const char *args)
{
	REDIRECT_REC *rec;
	GSList *list;
	char **arglist;
	int found;

	g_return_val_if_fail(IS_SERVER(server), NULL);
	g_return_val_if_fail(event != NULL, NULL);

	list = g_hash_table_lookup(server->eventtable, event);

	for (; list != NULL; list = list->next) {
		rec = list->data;
		if (rec->argpos == -1)
			break;

		if (rec->arg == NULL || args == NULL)
			continue;

		/* we need to check that the argument is right.. */
		arglist = g_strsplit(args, " ", -1);
		found = (strarray_length(arglist) > rec->argpos &&
			 find_substr(rec->arg, arglist[rec->argpos]));
		g_strfreev(arglist);

		if (found) break;
	}

	return list;
}

void servers_redirect_init(void)
{
	redirect_group = 0;

	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}

void servers_redirect_deinit(void)
{
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}
