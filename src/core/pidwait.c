/*
 pidwait.c :

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
#include "signals.h"
#include "modules.h"

static GHashTable *child_pids;
static GSList *pids;

static int signal_pidwait;

static void sig_child(GPid pid, gint status, gpointer data)
{
	signal_emit_id(signal_pidwait, 2, GINT_TO_POINTER(pid),
		       GINT_TO_POINTER(status));
	g_hash_table_remove(child_pids, GINT_TO_POINTER(pid));
	pids = g_slist_remove(pids, GINT_TO_POINTER(pid));
}

/* add a pid to wait list */
void pidwait_add(int pid)
{
	if (g_hash_table_lookup(child_pids, GINT_TO_POINTER(pid)) == NULL) {
		int id = g_child_watch_add_full(10, pid, sig_child, NULL, NULL);
		g_hash_table_insert(child_pids, GINT_TO_POINTER(pid), GINT_TO_POINTER(id));
		pids = g_slist_append(pids, GINT_TO_POINTER(pid));
	}
}

/* remove pid from wait list */
void pidwait_remove(int pid)
{
	gpointer id = g_hash_table_lookup(child_pids, GINT_TO_POINTER(pid));
	if (id != NULL) {
		g_source_remove(GPOINTER_TO_INT(id));
		g_hash_table_remove(child_pids, GINT_TO_POINTER(pid));
		pids = g_slist_remove(pids, GINT_TO_POINTER(pid));
	}
}

/* return list of pids that are being waited.
   don't free the return value. */
GSList *pidwait_get_pids(void)
{
        return pids;
}

void pidwait_init(void)
{
	child_pids = g_hash_table_new(g_direct_hash, g_direct_equal);
	pids = NULL;

	signal_pidwait = signal_get_uniq_id("pidwait");
}

void pidwait_deinit(void)
{
	g_hash_table_destroy(child_pids);
	g_slist_free(pids);
}
