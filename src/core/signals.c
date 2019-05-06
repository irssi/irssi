/*
 signals.c : irssi

    Copyright (C) 1999-2002 Timo Sirainen

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
#include <irssi/src/core/modules.h>

typedef struct _SignalHook {
	struct _SignalHook *next;

        int priority;
	const char *module;
	SIGNAL_FUNC func;
	void *user_data;
} SignalHook;

typedef struct {
	int id; /* signal id */
        int refcount;

	int emitting; /* signal is being emitted */
	int stop_emit; /* this signal was stopped */
	int continue_emit; /* this signal emit was continued elsewhere */
        int remove_count; /* hooks were removed from signal */

        SignalHook *hooks;
} Signal;

void *signal_user_data;

static GHashTable *signals;
static Signal *current_emitted_signal;
static SignalHook *current_emitted_hook;

#define signal_ref(signal) ++(signal)->refcount
#define signal_unref(signal) (signal_unref_full(signal, TRUE))

static int signal_unref_full(Signal *rec, int remove)
{
        g_assert(rec->refcount > 0);

	if (--rec->refcount != 0)
		return TRUE;

	/* remove whole signal from memory */
	if (rec->hooks != NULL) {
		g_error("signal_unref(%s) : BUG - hook list wasn't empty",
			signal_get_id_str(rec->id));
	}

	if (remove)
		g_hash_table_remove(signals, GINT_TO_POINTER(rec->id));
        g_free(rec);

	return FALSE;
}

static void signal_hash_ref(void *key, Signal *rec)
{
	signal_ref(rec);
}

static int signal_hash_unref(void *key, Signal *rec)
{
	return !signal_unref_full(rec, FALSE);
}

void signal_add_full(const char *module, int priority,
		     const char *signal, SIGNAL_FUNC func, void *user_data)
{
	signal_add_full_id(module, priority, signal_get_uniq_id(signal),
			   func, user_data);
}

/* bind a signal */
void signal_add_full_id(const char *module, int priority,
			int signal_id, SIGNAL_FUNC func, void *user_data)
{
	Signal *signal;
        SignalHook *hook, **tmp;

	g_return_if_fail(signal_id >= 0);
	g_return_if_fail(func != NULL);

	signal = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (signal == NULL) {
                /* new signal */
		signal = g_new0(Signal, 1);
		signal->id = signal_id;
		g_hash_table_insert(signals, GINT_TO_POINTER(signal_id), signal);
	}

	hook = g_new0(SignalHook, 1);
	hook->priority = priority;
	hook->module = module;
	hook->func = func;
	hook->user_data = user_data;

	/* insert signal to proper position in list */
	for (tmp = &signal->hooks; ; tmp = &(*tmp)->next) {
		if (*tmp == NULL) {
                        /* last in list */
			*tmp = hook;
                        break;
		} else if (priority <= (*tmp)->priority) {
                        /* insert before others with same priority */
			hook->next = *tmp;
			*tmp = hook;
                        break;
		}
	}

        signal_ref(signal);
}

static void signal_remove_hook(Signal *rec, SignalHook **hook_pos)
{
	SignalHook *hook;

        hook = *hook_pos;
        *hook_pos = hook->next;

	g_free(hook);

	signal_unref(rec);
}

/* Remove function from signal's emit list */
static int signal_remove_func(Signal *rec, SIGNAL_FUNC func, void *user_data)
{
        SignalHook **hook;

	for (hook = &rec->hooks; *hook != NULL; hook = &(*hook)->next) {
		if ((*hook)->func == func && (*hook)->user_data == user_data) {
			if (rec->emitting) {
				/* mark it removed after emitting is done */
				(*hook)->func = NULL;
                                rec->remove_count++;
			} else {
				/* remove the function from emit list */
				signal_remove_hook(rec, hook);
			}
			return TRUE;
		}
	}

        return FALSE;
}

void signal_remove_id(int signal_id, SIGNAL_FUNC func, void *user_data)
{
	Signal *rec;

	g_return_if_fail(signal_id >= 0);
	g_return_if_fail(func != NULL);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
        if (rec != NULL)
                signal_remove_func(rec, func, user_data);
}

/* unbind signal */
void signal_remove_full(const char *signal, SIGNAL_FUNC func, void *user_data)
{
	g_return_if_fail(signal != NULL);

	signal_remove_id(signal_get_uniq_id(signal), func, user_data);
}

static void signal_hooks_clean(Signal *rec)
{
	SignalHook **hook, **next;
        int count;

        count = rec->remove_count;
        rec->remove_count = 0;

	for (hook = &rec->hooks; *hook != NULL; hook = next) {
		next = &(*hook)->next;

		if ((*hook)->func == NULL) {
                        next = hook;
			signal_remove_hook(rec, hook);

			if (--count == 0)
                                break;
		}
	}
}

static int signal_emit_real(Signal *rec, int params, va_list va,
			    SignalHook *first_hook)
{
	const void *arglist[SIGNAL_MAX_ARGUMENTS];
	Signal *prev_emitted_signal;
        SignalHook *hook, *prev_emitted_hook;
	int i, stopped, stop_emit_count, continue_emit_count;

	for (i = 0; i < SIGNAL_MAX_ARGUMENTS; i++)
		arglist[i] = i >= params ? NULL : va_arg(va, const void *);

	/* signal_stop_by_name("signal"); signal_emit("signal", ...);
	   fails if we compare rec->stop_emit against 0. */
	stop_emit_count = rec->stop_emit;
	continue_emit_count = rec->continue_emit;

        signal_ref(rec);

	stopped = FALSE;
	rec->emitting++;

	prev_emitted_signal = current_emitted_signal;
	prev_emitted_hook = current_emitted_hook;
	current_emitted_signal = rec;

	for (hook = first_hook; hook != NULL; hook = hook->next) {
		if (hook->func == NULL)
			continue; /* removed */

		current_emitted_hook = hook;
#if SIGNAL_MAX_ARGUMENTS != 6
#  error SIGNAL_MAX_ARGUMENTS changed - update code
#endif
                signal_user_data = hook->user_data;
		hook->func(arglist[0], arglist[1], arglist[2], arglist[3],
			   arglist[4], arglist[5]);

		if (rec->continue_emit != continue_emit_count)
			rec->continue_emit--;

		if (rec->stop_emit != stop_emit_count) {
			stopped = TRUE;
			rec->stop_emit--;
			break;
		}
	}

	current_emitted_signal = prev_emitted_signal;
	current_emitted_hook = prev_emitted_hook;

	rec->emitting--;
	signal_user_data = NULL;

	if (!rec->emitting) {
		g_assert(rec->stop_emit == 0);
		g_assert(rec->continue_emit == 0);

                if (rec->remove_count > 0)
			signal_hooks_clean(rec);
	}

        signal_unref(rec);
	return stopped;
}

int signal_emit(const char *signal, int params, ...)
{
	Signal *rec;
	va_list va;
	int signal_id;

	g_return_val_if_fail(params >= 0 && params <= SIGNAL_MAX_ARGUMENTS, FALSE);

	signal_id = signal_get_uniq_id(signal);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (rec != NULL) {
		va_start(va, params);
		signal_emit_real(rec, params, va, rec->hooks);
		va_end(va);
	}

	return rec != NULL;
}

int signal_emit_id(int signal_id, int params, ...)
{
	Signal *rec;
	va_list va;

	g_return_val_if_fail(signal_id >= 0, FALSE);
	g_return_val_if_fail(params >= 0 && params <= SIGNAL_MAX_ARGUMENTS, FALSE);

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	if (rec != NULL) {
		va_start(va, params);
		signal_emit_real(rec, params, va, rec->hooks);
		va_end(va);
	}

	return rec != NULL;
}

void signal_continue(int params, ...)
{
	Signal *rec;
	va_list va;

	rec = current_emitted_signal;
	if (rec == NULL || rec->emitting <= rec->continue_emit)
		g_warning("signal_continue() : no signals are being emitted currently");
	else {
		va_start(va, params);

		/* stop the signal */
		if (rec->emitting > rec->stop_emit)
			rec->stop_emit++;

		/* re-emit */
		rec->continue_emit++;
		signal_emit_real(rec, params, va, current_emitted_hook->next);
		va_end(va);
	}
}

/* stop the current ongoing signal emission */
void signal_stop(void)
{
	Signal *rec;

	rec = current_emitted_signal;
	if (rec == NULL)
		g_warning("signal_stop() : no signals are being emitted currently");
	else if (rec->emitting > rec->stop_emit)
		rec->stop_emit++;
}

/* stop ongoing signal emission by signal name */
void signal_stop_by_name(const char *signal)
{
	Signal *rec;
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
	Signal *rec;

	rec = current_emitted_signal;
        g_return_val_if_fail(rec != NULL, -1);
	return rec->id;
}

/* return TRUE if specified signal was stopped */
int signal_is_stopped(int signal_id)
{
	Signal *rec;

	rec = g_hash_table_lookup(signals, GINT_TO_POINTER(signal_id));
	g_return_val_if_fail(rec != NULL, FALSE);

        return rec->emitting <= rec->stop_emit;
}

static void signal_remove_module(void *signal, Signal *rec,
				 const char *module)
{
	SignalHook **hook, **next;

	for (hook = &rec->hooks; *hook != NULL; hook = next) {
		next = &(*hook)->next;

		if (strcasecmp((*hook)->module, module) == 0) {
                        next = hook;
			signal_remove_hook(rec, hook);
		}
	}
}

/* remove all signals that belong to `module' */
void signals_remove_module(const char *module)
{
	g_return_if_fail(module != NULL);

	g_hash_table_foreach(signals, (GHFunc) signal_hash_ref, NULL);
	g_hash_table_foreach(signals, (GHFunc) signal_remove_module,
			     (void *) module);
	g_hash_table_foreach_remove(signals, (GHRFunc) signal_hash_unref, NULL);
}

void signals_init(void)
{
	signals = g_hash_table_new(NULL, NULL);
}

static void signal_free(void *key, Signal *rec)
{
	/* refcount-1 because we just referenced it ourself */
	g_warning("signal_free(%s) : signal still has %d references:",
		  signal_get_id_str(rec->id), rec->refcount-1);

	while (rec->hooks != NULL) {
		g_warning(" - module '%s' function %p",
			  rec->hooks->module, rec->hooks->func);

		signal_remove_hook(rec, &rec->hooks);
	}
}

void signals_deinit(void)
{
	g_hash_table_foreach(signals, (GHFunc) signal_hash_ref, NULL);
        g_hash_table_foreach(signals, (GHFunc) signal_free, NULL);
	g_hash_table_foreach_remove(signals, (GHRFunc) signal_hash_unref, NULL);
	g_hash_table_destroy(signals);

	module_uniq_destroy("signals");
}
