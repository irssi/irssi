/*
 dcc-queue.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

    DCC queue by Heikki Orsila <heikki.orsila@tut.fi> (no copyrights claimed)

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
#include "signals.h"
#include "commands.h"
#include "network.h"
#include "net-sendbuffer.h"
#include "misc.h"
#include "settings.h"
#include "irc-servers.h"

#include "dcc-queue.h"

static GPtrArray *queuelist;

/* dcc_queue_old finds an old queue (if it exists) */
int dcc_queue_old(const char *nick, const char *servertag)
{
	int i;

	for (i = 0; i < queuelist->len; i++) {
		GSList *qlist = g_ptr_array_index(queuelist, i);

		for (; qlist != NULL; qlist = qlist->next) {
			DCC_QUEUE_REC *rec = qlist->data;

			if (rec == NULL)
				continue;

			if (*nick != '\0' && g_strcasecmp(nick, rec->nick) != 0)
				continue;

			if (*servertag != '\0' &&
			    g_strcasecmp(servertag, rec->servertag) != 0)
				continue;

			/* found a queue matching nick/server! */
			return i;
		}
	}

	return -1;
}


int dcc_queue_new(void)
{
	int i;

	for (i = 0; i < queuelist->len; i++) {
		if (g_ptr_array_index(queuelist, i) == NULL)
			break;
	}

	if (i == queuelist->len)
		g_ptr_array_set_size(queuelist, (i + 1) * 2);

	/* create stub */
        g_ptr_array_index(queuelist, i) = g_slist_append(NULL, NULL);
	return i;
}

static void dcc_queue_free_rec(DCC_QUEUE_REC *rec)
{
	if (rec != NULL) {
		g_free(rec->servertag);
		g_free(rec->nick);
		g_free(rec->file);
		g_free(rec);
	}
}

void dcc_queue_free(int queue)
{
	GSList **qlist;

	g_assert(queue >= 0 && queue < queuelist->len);

	qlist = (GSList **) &g_ptr_array_index(queuelist, queue);
	while (*qlist != NULL) {
		DCC_QUEUE_REC *rec = (*qlist)->data;

		*qlist = (*qlist)->next;
		dcc_queue_free_rec(rec);
	}
}

/* add an element to queue. element will have nick/servertag/fname/chat as data.
   mode specifies how the element should be added (append or prepend)
*/

void dcc_queue_add(int queue, int mode, const char *nick, const char *fname,
		   const char *servertag, CHAT_DCC_REC *chat, int passive)
{
	DCC_QUEUE_REC *rec;
	GSList **qlist;

	g_assert(queue >= 0 && queue < queuelist->len);

	rec = g_new0(DCC_QUEUE_REC, 1);
	rec->chat = chat;
	rec->servertag = g_strdup(servertag);
	rec->nick = g_strdup(nick);
	rec->file = g_strdup(fname);
	rec->passive = passive;

	qlist = (GSList **) &g_ptr_array_index(queuelist, queue);
	if (mode == DCC_QUEUE_PREPEND)
		*qlist = g_slist_insert(*qlist, rec, 1);
	else
		*qlist = g_slist_append(*qlist, rec);
}

/* removes the head or the tail from the queue. returns the number of
   elements removed from the queue (0 or 1). if remove_head is non-zero,
   the head is removed (or actually stub is removed and the current head
   becomes the stub), otherwise the tail is removed. */
static int dcc_queue_remove_entry(int queue, int remove_head)
{
	DCC_QUEUE_REC *rec;
	GSList **qlist;

	g_assert(queue >= 0 && queue < queuelist->len);

	qlist = (GSList **) &g_ptr_array_index(queuelist, queue);
	if (*qlist == NULL || (*qlist)->next == NULL)
		return 0;

	rec = remove_head ? (*qlist)->data : g_slist_last(*qlist)->data;
	*qlist = g_slist_remove(*qlist, rec);

	dcc_queue_free_rec(rec);
	return 1;
}

/* removes the head, but not stub from the queue. returns number of elements
   removed from the queue (0 or 1) */
int dcc_queue_remove_head(int queue)
{
	return dcc_queue_remove_entry(queue, 1);
}

/* removes the tail, but not stub from the queue. returns number of elements
   removed from the queue (0 or 1) */
int dcc_queue_remove_tail(int queue)
{
	return dcc_queue_remove_entry(queue, 0);
}

DCC_QUEUE_REC *dcc_queue_get_next(int queue)
{
	GSList *qlist;

	g_assert(queue >= 0 && queue < queuelist->len);

	qlist = g_ptr_array_index(queuelist, queue);
	return qlist == NULL || qlist->next == NULL ? NULL : qlist->next->data;
}

GSList *dcc_queue_get_queue(int queue)
{
	GSList *qlist;

	g_assert(queue >= 0 && queue < queuelist->len);

	qlist = g_ptr_array_index(queuelist, queue);
	return qlist == NULL ? NULL : qlist->next;
}

static void sig_dcc_destroyed(CHAT_DCC_REC *dcc)
{
	int i;

	if (!IS_DCC_CHAT(dcc))
		return;

	for (i = 0; i < queuelist->len; i++) {
		GSList *qlist = g_ptr_array_index(queuelist, i);

		for (; qlist != NULL; qlist = qlist->next) {
			DCC_QUEUE_REC *rec = qlist->data;

			if (rec != NULL && rec->chat == dcc)
				rec->chat = NULL;
	       }
	}
}

void dcc_queue_init(void)
{
	queuelist = g_ptr_array_new();

	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
}

void dcc_queue_deinit(void)
{
	int i;

	for (i = 0; i < queuelist->len; i++)
		dcc_queue_free(i);

	g_ptr_array_free(queuelist, TRUE);

	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
}
