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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#define NEED_PERL_H
#define PERL_NO_GET_CONTEXT
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
} PERL_SIGNAL_REC;

typedef struct {
	char *signal;
	char *args[7];
	int dynamic;
} PERL_SIGNAL_ARGS_REC;

#include "perl-signals-list.h"

static GHashTable *signals;
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

void perl_signal_args_to_c(
        void (*callback)(void *, void **), void *cb_arg,
        int signal_id, SV **args, size_t n_args)
{
        union {
                int v_int;
                unsigned long v_ulong;
                GSList *v_gslist;
                GList *v_glist;
        } saved_args[SIGNAL_MAX_ARGUMENTS];
        void *p[SIGNAL_MAX_ARGUMENTS];
        PERL_SIGNAL_ARGS_REC *rec;
        size_t n;

        if (!(rec = perl_signal_args_find(signal_id))) {
                const char *name = signal_get_id_str(signal_id);
                if (!name) {
                        croak("%d is not a known signal id", signal_id);
                }
                croak("\"%s\" is not a registered signal", name);
        }

        for (n = 0; n < SIGNAL_MAX_ARGUMENTS && n < n_args && rec->args[n] != NULL; ++n) {
                void *c_arg;
                SV *arg = args[n];

                if (!SvOK(arg)) {
                        c_arg = NULL;
                } else if (g_strcmp0(rec->args[n], "string") == 0) {
                        c_arg = SvPV_nolen(arg);
                } else if (g_strcmp0(rec->args[n], "int") == 0) {
                        c_arg = (void *)SvIV(arg);
                } else if (g_strcmp0(rec->args[n], "ulongptr") == 0) {
                        saved_args[n].v_ulong = SvUV(arg);
                        c_arg = &saved_args[n].v_ulong;
                } else if (g_strcmp0(rec->args[n], "intptr") == 0) {
                        saved_args[n].v_int = SvIV(SvRV(arg));
                        c_arg = &saved_args[n].v_int;
                } else if (strncmp(rec->args[n], "glistptr_", 9) == 0) {
                        GList *gl;
                        int is_str;
                        AV *av;
                        SV *t;
                        int count;

                        t = SvRV(arg);
                        if (SvTYPE(t) != SVt_PVAV) {
                                croak("Not an ARRAY reference");
                        }
                        av = (AV *)t;

                        is_str = g_strcmp0(rec->args[n]+9, "char*") == 0;

                        gl = NULL;
                        count = av_len(av) + 1;
                        while (count-- > 0) {
                                SV **px = av_fetch(av, count, 0);
                                SV *x = px ? *px : NULL;
                                gl = g_list_prepend(
                                        gl,
                                        x == NULL ? NULL :
                                        is_str ? g_strdup(SvPV_nolen(x)) :
                                        irssi_ref_object(x)
                                );
                        }
                        saved_args[n].v_glist = gl;
                        c_arg = &saved_args[n].v_glist;
                } else if (strncmp(rec->args[n], "gslist_", 7) == 0) {
                        GSList *gsl;
                        AV *av;
                        SV *t;
                        int count;

                        t = SvRV(arg);
                        if (SvTYPE(t) != SVt_PVAV) {
                                croak("Not an ARRAY reference");
                        }
                        av = (AV *)t;

                        gsl = NULL;
                        count = av_len(av) + 1;
                        while (count-- > 0) {
                                SV **x = av_fetch(av, count, 0);
                                gsl = g_slist_prepend(
                                        gsl,
                                        x == NULL ? NULL :
                                        irssi_ref_object(*x)
                                );
                        }
                        c_arg = saved_args[n].v_gslist = gsl;
                } else {
                        c_arg = irssi_ref_object(arg);
                }

                p[n] = c_arg;
        }

        for (; n < SIGNAL_MAX_ARGUMENTS; ++n) {
                p[n] = NULL;
        }

        callback(cb_arg, p);

        for (n = 0; n < SIGNAL_MAX_ARGUMENTS && n < n_args && rec->args[n] != NULL; ++n) {
                SV *arg = args[n];

                if (!SvOK(arg)) {
                        continue;
                }

                if (g_strcmp0(rec->args[n], "intptr") == 0) {
                        SV *t = SvRV(arg);
                        SvIOK_only(t);
                        SvIV_set(t, saved_args[n].v_int);
                } else if (strncmp(rec->args[n], "gslist_", 7) == 0) {
                        g_slist_free(saved_args[n].v_gslist);
                } else if (strncmp(rec->args[n], "glistptr_", 9) == 0) {
                        int is_iobject, is_str;
                        AV *av;
                        GList *gl, *tmp;

                        is_iobject = g_strcmp0(rec->args[n]+9, "iobject") == 0;
                        is_str = g_strcmp0(rec->args[n]+9, "char*") == 0;

                        av = (AV *)SvRV(arg);
                        av_clear(av);

                        gl = saved_args[n].v_glist;
                        for (tmp = gl; tmp != NULL; tmp = tmp->next) {
                                av_push(av,
                                        is_iobject ? iobject_bless((SERVER_REC *)tmp->data) :
                                        is_str ? new_pv(tmp->data) :
                                        irssi_bless_plain(rec->args[n]+9, tmp->data)
                                );
                        }

                        if (is_str) {
                                g_list_foreach(gl, (GFunc)g_free, NULL);
                        }
                        g_list_free(gl);
                }
        }
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

                if (strncmp(rec->args[n], "glistptr_", 9) == 0) {
			/* pointer to linked list - push as AV */
			GList *tmp, **ptr;
                        int is_iobject, is_str;

                        is_iobject = g_strcmp0(rec->args[n]+9, "iobject") == 0;
                        is_str = g_strcmp0(rec->args[n]+9, "char*") == 0;
			av = newAV();

			ptr = arg;
			for (tmp = *ptr; tmp != NULL; tmp = tmp->next) {
				sv = is_iobject ? iobject_bless((SERVER_REC *) tmp->data) :
					is_str ? new_pv(tmp->data) :
					irssi_bless_plain(rec->args[n]+9, tmp->data);
				av_push(av, sv);
			}

			saved_args[n] = perlarg = newRV_noinc((SV *) av);
                } else if (g_strcmp0(rec->args[n], "int") == 0)
                        perlarg = newSViv((IV)arg);
                else if (arg == NULL)
                        perlarg = &PL_sv_undef;
                else if (g_strcmp0(rec->args[n], "string") == 0)
                        perlarg = new_pv(arg);
                else if (g_strcmp0(rec->args[n], "ulongptr") == 0)
                        perlarg = newSViv(*(unsigned long *) arg);
                else if (g_strcmp0(rec->args[n], "intptr") == 0)
                        saved_args[n] = perlarg = newRV_noinc(newSViv(*(int *) arg));
                else if (strncmp(rec->args[n], "gslist_", 7) == 0) {
			/* linked list - push as AV */
			GSList *tmp;
			int is_iobject;

                        is_iobject = g_strcmp0(rec->args[n]+7, "iobject") == 0;
			av = newAV();
			for (tmp = arg; tmp != NULL; tmp = tmp->next) {
				sv = is_iobject ? iobject_bless((SERVER_REC *) tmp->data) :
					irssi_bless_plain(rec->args[n]+7, tmp->data);
				av_push(av, sv);
			}

			perlarg = newRV_noinc((SV *) av);
		} else if (g_strcmp0(rec->args[n], "iobject") == 0) {
			/* "irssi object" - any struct that has
			   "int type; int chat_type" as it's first
			   variables (server, channel, ..) */
			perlarg = iobject_bless((SERVER_REC *) arg);
		} else if (g_strcmp0(rec->args[n], "siobject") == 0) {
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
		char *error = g_strdup(SvPV_nolen(ERRSV));
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

		if (g_strcmp0(rec->args[n], "intptr") == 0) {
			int *val = arg;
			*val = SvIV(SvRV(saved_args[n]));
		} else if (strncmp(rec->args[n], "glistptr_", 9) == 0) {
                        GList **ret = arg;
			GList *out = NULL;
                        void *val;
                        int count;

			av = (AV *) SvRV(saved_args[n]);
                        count = av_len(av);
			while (count-- >= 0) {
				sv = av_shift(av);
				if (SvPOKp(sv))
					val = g_strdup(SvPV_nolen(sv));
				else
                                        val = GINT_TO_POINTER(SvIV(sv));

				out = g_list_append(out, val);
			}

			if (g_strcmp0(rec->args[n]+9, "char*") == 0)
                                g_list_foreach(*ret, (GFunc) g_free, NULL);
			g_list_free(*ret);
                        *ret = out;
		}
	}

	FREETMPS;
	LEAVE;
}

static void sig_func(const void *p1, const void *p2,
		     const void *p3, const void *p4,
		     const void *p5, const void *p6)
{
	PERL_SIGNAL_REC *rec;
	const void *args[6];

	args[0] = p1; args[1] = p2; args[2] = p3;
	args[3] = p4; args[4] = p5; args[5] = p6;

	rec = signal_get_user_data();
	perl_call_signal(rec->script, rec->func, signal_get_emitted_id(), args);
}

static void perl_signal_add_full_int(const char *signal, SV *func,
				     int priority, int command,
				     const char *category)
{
        PERL_SCRIPT_REC *script;
	PERL_SIGNAL_REC *rec;
	GSList **siglist;
	void *signal_idp;

        g_return_if_fail(signal != NULL);
        g_return_if_fail(func != NULL);

        script = perl_script_find_package(perl_get_package());
        g_return_if_fail(script != NULL);

	rec = g_new(PERL_SIGNAL_REC, 1);
        rec->script = script;
	rec->signal_id = signal_get_uniq_id(signal);
	rec->signal = g_strdup(signal);
	rec->func = perl_func_sv_inc(func, perl_get_package());

	if (command || strncmp(signal, "command ", 8) == 0) {
		/* we used Irssi::signal_add() instead of
		   Irssi::command_bind() - oh well, allow this.. */
		command_bind_full(MODULE_NAME, priority, signal+8, -1,
				  category, sig_func, rec);
	} else {
		signal_add_full_id(MODULE_NAME, priority, rec->signal_id,
				   sig_func, rec);
	}

	signal_idp = GINT_TO_POINTER(rec->signal_id);
	siglist = g_hash_table_lookup(signals, signal_idp);
	if (siglist == NULL) {
		siglist = g_new0(GSList *, 1);
		g_hash_table_insert(signals, signal_idp, siglist);
	}

	*siglist = g_slist_append(*siglist, rec);
}

void perl_signal_add_full(const char *signal, SV *func, int priority)
{
        perl_signal_add_full_int(signal, func, priority, FALSE, NULL);
}

static void perl_signal_destroy(PERL_SIGNAL_REC *rec)
{
	if (strncmp(rec->signal, "command ", 8) == 0)
		command_unbind_full(rec->signal+8, sig_func, rec);
	else
		signal_remove_id(rec->signal_id, sig_func, rec);

        SvREFCNT_dec(rec->func);
	g_free(rec->signal);
	g_free(rec);
}

static void perl_signal_remove_list_one(GSList **siglist, PERL_SIGNAL_REC *rec)
{
	*siglist = g_slist_remove(*siglist, rec);
	if (*siglist == NULL) {
		g_free(siglist);
		g_hash_table_remove(signals, GINT_TO_POINTER(rec->signal_id));
	}

        perl_signal_destroy(rec);
}

#define sv_func_cmp(f1, f2) \
	((SvROK(f1) && SvROK(f2) && SvRV(f1) == SvRV(f2)) || \
	 (SvPOK(f1) && SvPOK(f2) && \
	  g_strcmp0(SvPV_nolen(f1), SvPV_nolen(f2)) == 0))

static void perl_signal_remove_list(GSList **list, SV *func)
{
	GSList *tmp;

	for (tmp = *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (sv_func_cmp(rec->func, func)) {
			perl_signal_remove_list_one(list, rec);
			break;
		}
	}
}

void perl_signal_remove(const char *signal, SV *func)
{
	GSList **list;
        void *signal_idp;

	signal_idp = GINT_TO_POINTER(signal_get_uniq_id(signal));
	list = g_hash_table_lookup(signals, signal_idp);

	if (list != NULL) {
		func = perl_func_sv_inc(func, perl_get_package());
		perl_signal_remove_list(list, func);
		SvREFCNT_dec(func);
	}
}

void perl_command_bind_to(const char *cmd, const char *category,
			  SV *func, int priority)
{
	char *signal;

	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_add_full_int(signal, func, priority, TRUE, category);
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
	g_hash_table_foreach_remove(signals, (GHRFunc) signal_destroy_hash,
				    script);
}

void perl_signals_start(void)
{
	signals = g_hash_table_new(NULL, NULL);
}

void perl_signals_stop(void)
{
	g_hash_table_foreach(signals, (GHFunc) signal_destroy_hash, NULL);
	g_hash_table_destroy(signals);
	signals = NULL;
}

static void register_signal_rec(PERL_SIGNAL_ARGS_REC *rec)
{
	if (rec->signal[strlen(rec->signal)-1] == ' ') {
		perl_signal_args_partial =
			g_slist_append(perl_signal_args_partial, rec);
	} else {
		int signal_id = signal_get_uniq_id(rec->signal);
		g_hash_table_insert(perl_signal_args_hash,
				    GINT_TO_POINTER(signal_id), rec);
	}
}

void perl_signal_register(const char *signal, const char **args)
{
	PERL_SIGNAL_ARGS_REC *rec;
	int i;

	if (perl_signal_args_find(signal_get_uniq_id(signal)) != NULL)
		return;

	rec = g_new0(PERL_SIGNAL_ARGS_REC, 1);
	for (i = 0; i < 6 && args[i] != NULL; i++)
		rec->args[i] = g_strdup(args[i]);
	rec->dynamic = TRUE;
	rec->signal = g_strdup(signal);
	register_signal_rec(rec);
}

void perl_signals_init(void)
{
	int n;

	perl_signal_args_hash = g_hash_table_new((GHashFunc) g_direct_hash,
						 (GCompareFunc) g_direct_equal);
        perl_signal_args_partial = NULL;

	for (n = 0; perl_signal_args[n].signal != NULL; n++)
		register_signal_rec(&perl_signal_args[n]);
}

static void signal_args_free(PERL_SIGNAL_ARGS_REC *rec)
{
	int i;

	if (!rec->dynamic)
		return;

	for (i = 0; i < 6 && rec->args[i] != NULL; i++)
		g_free(rec->args[i]);
	g_free(rec->signal);
	g_free(rec);
}

static void signal_args_hash_free(void *key, PERL_SIGNAL_ARGS_REC *rec)
{
        signal_args_free(rec);
}

void perl_signals_deinit(void)
{
	g_slist_foreach(perl_signal_args_partial,
			(GFunc) signal_args_free, NULL);
	g_slist_free(perl_signal_args_partial);

	g_hash_table_foreach(perl_signal_args_hash,
			     (GHFunc) signal_args_hash_free, NULL);
        g_hash_table_destroy(perl_signal_args_hash);
}
