/*
 perl-signals.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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

#define NEED_PERL_H
#include "module.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "servers.h"

#include "perl-core.h"
#include "perl-common.h"
#include "perl-signals.h"

typedef struct {
        PERL_SCRIPT_REC *script;
	int signal_id;
	char *signal;

	SV *func;
	int priority;
} PERL_SIGNAL_REC;

typedef struct {
	char *signal;
	char *args[7];
} PERL_SIGNAL_ARGS_REC;

#include "perl-signals-list.h"

static GHashTable *signals[3];
static GHashTable *perl_signal_args_hash;
static GSList *perl_signal_args_partial;

static PERL_SIGNAL_ARGS_REC *perl_signal_args_find(int signal_id)
{
	PERL_SIGNAL_ARGS_REC *rec;
        GSList *tmp;
	const char *signame;

	rec = g_hash_table_lookup(perl_signal_args_hash,
				  GINT_TO_POINTER(signal_id));
        if (rec != NULL) return rec;

	/* try to find by name */
	signame = signal_get_id_str(signal_id);
	for (tmp = perl_signal_args_partial; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		if (strncmp(rec->signal, signame, strlen(rec->signal)) == 0)
			return rec;
	}

	return NULL;
}

static void perl_call_signal(PERL_SCRIPT_REC *script, SV *func,
			     int signal_id, gconstpointer *args)
{
	dSP;

	PERL_SIGNAL_ARGS_REC *rec;
	SV *sv, *perlarg, *saved_args[SIGNAL_MAX_ARGUMENTS];
	AV *av;
        void *arg;
	int n;


	ENTER;
	SAVETMPS;

	PUSHMARK(sp);

	/* push signal argument to perl stack */
	rec = perl_signal_args_find(signal_id);

        memset(saved_args, 0, sizeof(saved_args));
	for (n = 0; n < SIGNAL_MAX_ARGUMENTS &&
		    rec != NULL && rec->args[n] != NULL; n++) {
		arg = (void *) args[n];

		if (strcmp(rec->args[n], "string") == 0)
			perlarg = new_pv(arg);
		else if (strcmp(rec->args[n], "int") == 0)
			perlarg = newSViv(GPOINTER_TO_INT(arg));
		else if (strcmp(rec->args[n], "ulongptr") == 0)
			perlarg = newSViv(*(unsigned long *) arg);
		else if (strcmp(rec->args[n], "intptr") == 0)
			saved_args[n] = perlarg = newRV_noinc(newSViv(*(int *) arg));
		else if (strncmp(rec->args[n], "glistptr_", 9) == 0) {
			/* pointer to linked list - push as AV */
			GList *tmp, **ptr;
                        int is_iobject, is_str;

                        is_iobject = strcmp(rec->args[n]+9, "iobject") == 0;
                        is_str = strcmp(rec->args[n]+9, "char*") == 0;
			av = newAV();

			ptr = arg;
			for (tmp = *ptr; tmp != NULL; tmp = tmp->next) {
				sv = is_iobject ? iobject_bless((SERVER_REC *) tmp->data) :
					is_str ? new_pv(tmp->data) :
					irssi_bless_plain(rec->args[n]+9, tmp->data);
				av_push(av, sv);
			}

			saved_args[n] = perlarg = newRV_noinc((SV *) av);
		} else if (strncmp(rec->args[n], "gslist_", 7) == 0) {
			/* linked list - push as AV */
			GSList *tmp;
			int is_iobject;

                        is_iobject = strcmp(rec->args[n]+7, "iobject") == 0;
			av = newAV();
			for (tmp = arg; tmp != NULL; tmp = tmp->next) {
				sv = is_iobject ? iobject_bless((SERVER_REC *) tmp->data) :
					irssi_bless_plain(rec->args[n]+7, tmp->data);
				av_push(av, sv);
			}

			perlarg = newRV_noinc((SV *) av);
		} else if (arg == NULL) {
			/* don't bless NULL arguments */
			perlarg = newSViv(0);
		} else if (strcmp(rec->args[n], "iobject") == 0) {
			/* "irssi object" - any struct that has
			   "int type; int chat_type" as it's first
			   variables (server, channel, ..) */
			perlarg = iobject_bless((SERVER_REC *) arg);
		} else if (strcmp(rec->args[n], "siobject") == 0) {
			/* "simple irssi object" - any struct that has
			   int type; as it's first variable (dcc) */
			perlarg = simple_iobject_bless((SERVER_REC *) arg);
		} else {
			/* blessed object */
			perlarg = plain_bless(arg, rec->args[n]);
		}
		XPUSHs(sv_2mortal(perlarg));
	}

	PUTBACK;
	perl_call_sv(func, G_EVAL|G_DISCARD);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		char *error = g_strdup(SvPV(ERRSV, PL_na));
		signal_emit("script error", 2, script, error);
                g_free(error);
                rec = NULL;
	}

        /* restore arguments the perl script modified */
	for (n = 0; n < SIGNAL_MAX_ARGUMENTS &&
		    rec != NULL && rec->args[n] != NULL; n++) {
		arg = (void *) args[n];

		if (saved_args[n] == NULL)
                        continue;

		if (strcmp(rec->args[n], "intptr") == 0) {
			int *val = arg;
			*val = SvIV(SvRV(saved_args[n]));
		} else if (strncmp(rec->args[n], "glistptr_", 9) == 0) {
                        GList **ret = arg;
			GList *out = NULL;
                        void *val;
			STRLEN len;
                        int count;

			av = (AV *) SvRV(saved_args[n]);
                        count = av_len(av);
			while (count-- >= 0) {
				sv = av_shift(av);
				if (SvPOKp(sv))
					val = g_strdup(SvPV(sv, len));
				else
                                        val = GINT_TO_POINTER(SvIV(sv));

				out = g_list_append(out, val);
			}

			if (strcmp(rec->args[n]+9, "char*") == 0)
                                g_list_foreach(*ret, (GFunc) g_free, NULL);
			g_list_free(*ret);
                        *ret = out;
		}
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
}

static void sig_func(int priority, gconstpointer *args)
{
	GSList **list, *tmp, *next;
        int signal_id;

        signal_id = signal_get_emitted_id();
	list = g_hash_table_lookup(signals[priority],
				   GINT_TO_POINTER(signal_id));
	for (tmp = list == NULL ? NULL : *list; tmp != NULL; tmp = next) {
		PERL_SIGNAL_REC *rec = tmp->data;

                next = tmp->next;
		perl_call_signal(rec->script, rec->func, signal_id, args);
		if (signal_is_stopped(signal_id))
                        break;
	}
}

#define SIG_FUNC_DECL(priority, priority_name) \
static void sig_func_##priority_name(gconstpointer p1, gconstpointer p2, \
				     gconstpointer p3, gconstpointer p4, \
				     gconstpointer p5, gconstpointer p6) \
{ \
	gconstpointer args[6]; \
        args[0] = p1; args[1] = p2; args[2] = p3; \
        args[3] = p4; args[4] = p5; args[5] = p6; \
        sig_func(priority, args); \
}

SIG_FUNC_DECL(0, first);
SIG_FUNC_DECL(1, default);
SIG_FUNC_DECL(2, last);

#define priority_get_func(priority) \
	(priority == 0 ? sig_func_first : \
	priority == 1 ? sig_func_default : sig_func_last)

#define perl_signal_get_func(rec) \
	(priority_get_func((rec)->priority))

static void perl_signal_add_to_int(const char *signal, SV *func,
				   int priority, int command)
{
        PERL_SCRIPT_REC *script;
	PERL_SIGNAL_REC *rec;
	GHashTable *table;
	GSList **siglist;
	void *signal_idp;

        g_return_if_fail(signal != NULL);
        g_return_if_fail(func != NULL);
        g_return_if_fail(priority >= 0 && priority <= 2);

        script = perl_script_find_package(perl_get_package());
        g_return_if_fail(script != NULL);

	if (!command && strncmp(signal, "command ", 8) == 0) {
		/* we used Irssi::signal_add() instead of
		   Irssi::command_bind() - oh well, allow this.. */
		command_bind_to(MODULE_NAME, priority, signal+8, -1,
				NULL, priority_get_func(priority));
                command = TRUE;
	}

	rec = g_new(PERL_SIGNAL_REC, 1);
        rec->script = script;
	rec->signal_id = signal_get_uniq_id(signal);
	rec->signal = g_strdup(signal);
	rec->func = perl_func_sv_inc(func, perl_get_package());
	rec->priority = priority;

	table = signals[priority];
	signal_idp = GINT_TO_POINTER(rec->signal_id);

	siglist = g_hash_table_lookup(table, signal_idp);
	if (siglist == NULL) {
		siglist = g_new0(GSList *, 1);
		g_hash_table_insert(table, signal_idp, siglist);

		if (!command) {
			signal_add_to_id(MODULE_NAME, priority, rec->signal_id,
					 perl_signal_get_func(rec));
		}
	}

	*siglist = g_slist_append(*siglist, rec);
}

void perl_signal_add_to(const char *signal, SV *func, int priority)
{
        perl_signal_add_to_int(signal, func, priority, FALSE);
}

static void perl_signal_destroy(PERL_SIGNAL_REC *rec)
{
	if (strncmp(rec->signal, "command ", 8) == 0)
		command_unbind(rec->signal+8, perl_signal_get_func(rec));

        SvREFCNT_dec(rec->func);
	g_free(rec->signal);
	g_free(rec);
}

static void perl_signal_remove_list_one(GSList **siglist, PERL_SIGNAL_REC *rec)
{
	void *signal_idp;

	g_return_if_fail(rec != NULL);

	signal_idp = GINT_TO_POINTER(rec->signal_id);

	*siglist = g_slist_remove(*siglist, rec);
	if (*siglist == NULL) {
		signal_remove_id(rec->signal_id, perl_signal_get_func(rec));
		g_free(siglist);
		g_hash_table_remove(signals[rec->priority], signal_idp);
	}

        perl_signal_destroy(rec);
}

#define sv_func_cmp(f1, f2, len) \
	(f1 == f2 || (SvPOK(f1) && SvPOK(f2) && \
		strcmp((char *) SvPV(f1, len), (char *) SvPV(f2, len)) == 0))

static void perl_signal_remove_list(GSList **list, SV *func)
{
	GSList *tmp;

	g_return_if_fail(list != NULL);

	for (tmp = *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (sv_func_cmp(rec->func, func, PL_na)) {
			perl_signal_remove_list_one(list, rec);
			break;
		}
	}
}

void perl_signal_remove(const char *signal, SV *func)
{
	GSList **list;
        void *signal_idp;
	int n;

	signal_idp = GINT_TO_POINTER(signal_get_uniq_id(signal));

        func = perl_func_sv_inc(func, perl_get_package());
	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		list = g_hash_table_lookup(signals[n], signal_idp);
		if (list != NULL)
			perl_signal_remove_list(list, func);
	}
        SvREFCNT_dec(func);
}

void perl_command_bind_to(const char *cmd, const char *category,
			  SV *func, int priority)
{
	char *signal;

	command_bind_to(MODULE_NAME, priority, cmd, -1,
			category, priority_get_func(priority));

	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_add_to_int(signal, func, priority, TRUE);
	g_free(signal);
}

void perl_command_runsub(const char *cmd, const char *data, 
			 SERVER_REC *server, WI_ITEM_REC *item)
{
	command_runsub(cmd, data, server, item);
}

void perl_command_unbind(const char *cmd, SV *func)
{
	char *signal;

        /* perl_signal_remove() calls command_unbind() */
	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_remove(signal, func);
	g_free(signal);
}

static int signal_destroy_hash(void *key, GSList **list, PERL_SCRIPT_REC *script)
{
	GSList *tmp, *next;

	for (tmp = *list; tmp != NULL; tmp = next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		next = tmp->next;
		if (script == NULL || rec->script == script) {
			*list = g_slist_remove(*list, rec);
			if (*list == NULL) {
				signal_remove_id(rec->signal_id,
						 perl_signal_get_func(rec));
			}
			perl_signal_destroy(rec);
		}
	}

	if (*list != NULL)
		return FALSE;

	g_free(list);
	return TRUE;
}

/* destroy all signals used by script */
void perl_signal_remove_script(PERL_SCRIPT_REC *script)
{
	int n;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		g_hash_table_foreach_remove(signals[n],
					    (GHRFunc) signal_destroy_hash,
					    script);
	}
}

void perl_signals_start(void)
{
	int n;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		signals[n] = g_hash_table_new((GHashFunc) g_direct_hash,
					      (GCompareFunc) g_direct_equal);
	}
}

void perl_signals_stop(void)
{
	int n;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		g_hash_table_foreach(signals[n],
				     (GHFunc) signal_destroy_hash, NULL);
		g_hash_table_destroy(signals[n]);
                signals[n] = NULL;
	}
}

void perl_signals_init(void)
{
	int n;

	perl_signal_args_hash = g_hash_table_new((GHashFunc) g_direct_hash,
						 (GCompareFunc) g_direct_equal);
        perl_signal_args_partial = NULL;

	for (n = 0; perl_signal_args[n].signal != NULL; n++) {
		PERL_SIGNAL_ARGS_REC *rec = &perl_signal_args[n];

		if (rec->signal[strlen(rec->signal)-1] == ' ') {
			perl_signal_args_partial =
				g_slist_append(perl_signal_args_partial, rec);
		} else {
                        int signal_id = signal_get_uniq_id(rec->signal);
			g_hash_table_insert(perl_signal_args_hash,
					    GINT_TO_POINTER(signal_id),
					    rec);
		}
	}
}

void perl_signals_deinit(void)
{
        g_slist_free(perl_signal_args_partial);
        g_hash_table_destroy(perl_signal_args_hash);
}
