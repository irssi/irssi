/*
 signals.c : irssi

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

#include "../common.h"
#include "signals.h"
#include "modules.h"

#define SIGNAL_LISTS 3

typedef struct {
	int id; /* signal id */
        int refcount;

	int emitting; /* signal is being emitted */
	int stop_emit; /* this signal was stopped */

	GPtrArray *modulelist[SIGNAL_LISTS]; /* list of what signals belong
	                                        to which module */
	GPtrArray *siglist[SIGNAL_LISTS]; /* signal lists */
} SIGNAL_REC;

#define signal_is_emitlist_empty(a) \
	(!(a)->siglist[0] && !(a)->siglist[1] && !(a)->siglist[2])

static GMemChunk *signals_chunk;
static GHashTable *signals;
static SIGNAL_REC *current_emitted_signal;

#define signal_ref(signal) ++(signal)->refcount
#define signal_unref(rec) (signal_unref_full(rec, TRUE))

static int signal_unref_full(SIGNAL_REC *rec, int remove_hash)
{
	if (rec->refcount == 0) {
		g_error("signal_unref(%s) : BUG - reference counter == 0",
			signal_get_id_str(rec->id));
	}

	if (--rec->refcount != 0)
		return FALSE;

	/* remove whole signal from memory */
	if (!signal_is_emitlist_empty(rec)) {
		g_error("signal_unref(%s) : BUG - emitlist wasn't empty",
			signal_get_id_str(rec->id));
	}

	if (remove_hash)
		g_hash_table_remove(signals, GINT_TO_POINTER(rec->id));
	g_mem_chunk_free(signals_chunk, rec);
	return TRUE;
}

static void signal_unref_count(SIGNAL_REC *rec, int count)
{
	while (count-- > 0)
                signal_unref(rec);
}

void signal_add_to(const char *module, int pos,
		   const char *signal, SIGNAL_FUNC func)
{
	g_return_if_fail(signal != NULL);

	signal_add_to_id(module, pos, signal_get_uniq_id(signal), func);
}

/* bind a signal */
void signal_add_to_id(const char *module, int pos,
		      int signal_id, SIGNAL_FUNC func)
{
	SIGNAL_REC *rec;

	g_return_if_fail(signal_id >= 0);
	g_return_if_fail(func != NULL);
	g_return_if_fail(pos >= 0 && pos < SIGNAL_LISTS);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (rec == NULL) {
		rec = g_mem_chunk_alloc0(signals_chunk);
		rec->id = signal_id;
		g_hash_table_insert(signals, GINT_TO_POINTER(signal_id), rec);
	}

	if (rec->siglist[pos] == NULL) {
		rec->siglist[pos] = g_ptr_array_new();
		rec->modulelist[pos] = g_ptr_array_new();
	}

	g_ptr_array_add(rec->siglist[pos], (void *) func);
	g_ptr_array_add(rec->modulelist[pos], (void *) module);

        signal_ref(rec);
}

static int signal_list_find(GPtrArray *array, void *data)
{
	unsigned int n;

	for (n = 0; n < array->len; n++) {
		if (g_ptr_array_index(array, n) == data)
			return n;
	}

	return -1;
}

static void signal_list_free(SIGNAL_REC *rec, int list)
{
	g_ptr_array_free(rec->siglist[list], TRUE);
	g_ptr_array_free(rec->modulelist[list], TRUE);
	rec->siglist[list] = NULL;
	rec->modulelist[list] = NULL;
}

/* Returns TRUE if the whole signal is removed after this remove */
static void signal_remove_from_list(SIGNAL_REC *rec, int list, int index)
{
	g_ptr_array_remove_index(rec->siglist[list], index);
	g_ptr_array_remove_index(rec->modulelist[list], index);

	if (rec->siglist[list]->len == 0)
		signal_list_free(rec, list);

	signal_unref(rec);
}

/* Remove signal from emit lists */
static int signal_remove_from_lists(SIGNAL_REC *rec, SIGNAL_FUNC func)
{
	int n, index;

	for (n = 0; n < SIGNAL_LISTS; n++) {
		if (rec->siglist[n] == NULL)
			continue;

		index = signal_list_find(rec->siglist[n], (void *) func);
		if (index != -1) {
			/* remove the function from emit list */
			signal_remove_from_list(rec, n, index);
			return 1;
		}
	}

        return 0;
}

void signal_remove_id(int signal_id, SIGNAL_FUNC func)
{
	SIGNAL_REC *rec;

	g_return_if_fail(signal_id >= 0);
	g_return_if_fail(func != NULL);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
        if (rec != NULL)
		signal_remove_from_lists(rec, func);
}

/* unbind signal */
void signal_remove(const char *signal, SIGNAL_FUNC func)
{
	g_return_if_fail(signal != NULL);

	signal_remove_id(signal_get_uniq_id(signal), func);
}

static int signal_emit_real(SIGNAL_REC *rec, int params, va_list va)
{
	gconstpointer arglist[SIGNAL_MAX_ARGUMENTS];
        SIGNAL_REC *prev_emitted_signal;
        SIGNAL_FUNC func;
	int n, index, stopped, stop_emit_count;

	for (n = 0; n < SIGNAL_MAX_ARGUMENTS; n++)
		arglist[n] = n >= params ? NULL : va_arg(va, gconstpointer);

	/* signal_stop_by_name("signal"); signal_emit("signal", ...);
	   fails if we compare rec->stop_emit against 0. */
	stop_emit_count = rec->stop_emit;

        signal_ref(rec);

	stopped = FALSE;
	rec->emitting++;
	for (n = 0; n < SIGNAL_LISTS; n++) {
		/* run signals in emit lists */
		if (rec->siglist[n] == NULL)
			continue;

		for (index = rec->siglist[n]->len-1; index >= 0; index--) {
			func = (SIGNAL_FUNC) g_ptr_array_index(rec->siglist[n], index);

			prev_emitted_signal = current_emitted_signal;
			current_emitted_signal = rec;
#if SIGNAL_MAX_ARGUMENTS != 6
#  error SIGNAL_MAX_ARGUMENTS changed - update code
#endif
			func(arglist[0], arglist[1], arglist[2], arglist[3], arglist[4], arglist[5]);
			current_emitted_signal = prev_emitted_signal;

			if (rec->stop_emit != stop_emit_count) {
				stopped = TRUE;
				rec->stop_emit--;
				n = SIGNAL_LISTS;
				break;
			}
		}
	}
	rec->emitting--;

	if (!rec->emitting) {
		if (rec->stop_emit != 0) {
			/* signal_stop() used too many times */
                        rec->stop_emit = 0;
		}
	}

        signal_unref(rec);
	return stopped;
}

int signal_emit(const char *signal, int params, ...)
{
	SIGNAL_REC *rec;
	va_list va;
	int signal_id;

	g_return_val_if_fail(params >= 0 && params <= SIGNAL_MAX_ARGUMENTS, FALSE);

	signal_id = signal_get_uniq_id(signal);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (rec != NULL) {
		va_start(va, params);
		signal_emit_real(rec, params, va);
		va_end(va);
	}

	return rec != NULL;
}

int signal_emit_id(int signal_id, int params, ...)
{
	SIGNAL_REC *rec;
	va_list va;

	g_return_val_if_fail(signal_id >= 0, FALSE);
	g_return_val_if_fail(params >= 0 && params <= SIGNAL_MAX_ARGUMENTS, FALSE);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (rec != NULL) {
		va_start(va, params);
		signal_emit_real(rec, params, va);
		va_end(va);
	}

	return rec != NULL;
}

/* stop the current ongoing signal emission */
void signal_stop(void)
{
	SIGNAL_REC *rec;

	rec = current_emitted_signal;
	if (rec == NULL)
		g_warning("signal_stop() : no signals are being emitted currently");
	else if (rec->emitting > rec->stop_emit)
		rec->stop_emit++;
}

/* stop ongoing signal emission by signal name */
void signal_stop_by_name(const char *signal)
{
	SIGNAL_REC *rec;
	int signal_id;

	signal_id = signal_get_uniq_id(signal);
	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (rec == NULL)
		g_warning("signal_stop_by_name() : unknown signal \"%s\"", signal);
	else if (rec->emitting > rec->stop_emit)
		rec->stop_emit++;
}

/* return the name of the signal that is currently being emitted */
const char *signal_get_emitted(void)
{
	return signal_get_id_str(signal_get_emitted_id());
}

/* return the ID of the signal that is currently being emitted */
int signal_get_emitted_id(void)
{
	SIGNAL_REC *rec;

	rec = current_emitted_signal;
        g_return_val_if_fail(rec != NULL, -1);
	return rec->id;
}

/* return TRUE if specified signal was stopped */
int signal_is_stopped(int signal_id)
{
	SIGNAL_REC *rec;

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	g_return_val_if_fail(rec != NULL, FALSE);

        return rec->emitting <= rec->stop_emit;
}

static void signal_remove_module(void *signal, SIGNAL_REC *rec,
				 const char *module)
{
        unsigned int index;
	int list;

	for (list = 0; list < SIGNAL_LISTS; list++) {
		if (rec->modulelist[list] == NULL)
			continue;

		for (index = rec->modulelist[list]->len; index > 0; index--)
			if (g_strcasecmp(g_ptr_array_index(rec->modulelist[list], index-1), module) == 0)
				signal_remove_from_list(rec, list, index-1);
	}
}

static void signal_foreach_ref(void *signal, SIGNAL_REC *rec)
{
        signal_ref(rec);
}

static int signal_foreach_unref(void *signal, SIGNAL_REC *rec)
{
        return signal_unref_full(rec, FALSE);
}

/* remove all signals that belong to `module' */
void signals_remove_module(const char *module)
{
	g_return_if_fail(module != NULL);

	g_hash_table_foreach(signals, (GHFunc) signal_foreach_ref, NULL);
	g_hash_table_foreach(signals, (GHFunc) signal_remove_module, (void *) module);
	g_hash_table_foreach_remove(signals, (GHRFunc) signal_foreach_unref, NULL);
}

void signals_init(void)
{
	signals_chunk = g_mem_chunk_new("signals", sizeof(SIGNAL_REC),
					sizeof(SIGNAL_REC)*200, G_ALLOC_AND_FREE);
	signals = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
}

static void signal_free(void *key, SIGNAL_REC *rec)
{
	int n;

        signal_ref(rec);

	for (n = 0; n < SIGNAL_LISTS; n++) {
		if (rec->siglist[n] != NULL) {
			signal_unref_count(rec, rec->siglist[n]->len);
                        signal_list_free(rec, n);
		}
	}

	if (!signal_unref_full(rec, FALSE)) {
		g_error("signal_free(%s) : BUG - signal still has %d references",
			signal_get_id_str(rec->id), rec->refcount);
	}
}

void signals_deinit(void)
{
	g_hash_table_foreach(signals, (GHFunc) signal_free, NULL);
	g_hash_table_destroy(signals);

	module_uniq_destroy("signals");
	g_mem_chunk_destroy(signals_chunk);
}
