/*
 perl.c : irssi

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

#include <EXTERN.h>
#ifndef _SEM_SEMUN_UNDEFINED
#define HAS_UNION_SEMUN
#endif
#include <perl.h>

#undef _
#undef PACKAGE

#include "module.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"

extern void xs_init(void);

typedef struct {
	int signal_id;
	char *signal;
	char *args[7];
} PERL_SIGNAL_ARGS_REC;

typedef struct {
	char *signal;
	int signal_id;

	char *func;
	int last;
} PERL_SIGNAL_REC;

typedef struct {
	int tag;
	char *func;
	char *data;
} PERL_TIMEOUT_REC;

#include "perl-signals.h"

static GHashTable *first_signals, *last_signals;
static GSList *perl_timeouts;
static PerlInterpreter *irssi_perl_interp;
static int signal_grabbed, siglast_grabbed;

static void sig_signal(void *signal, ...);
static void sig_lastsignal(void *signal, ...);

static void perl_signal_destroy(PERL_SIGNAL_REC *rec)
{
	GHashTable *table;
	GSList *siglist;
	void *signal_idp;

	g_return_if_fail(rec != NULL);

	table = rec->last ? last_signals : first_signals;
	signal_idp = GINT_TO_POINTER(rec->signal_id);

	siglist = g_hash_table_lookup(table, signal_idp);
	if (siglist == NULL) return;

	siglist = g_slist_remove(siglist, rec);
	g_hash_table_remove(table, signal_idp);
	if (siglist != NULL) g_hash_table_insert(table, signal_idp, siglist);

	if (!rec->last && signal_grabbed && g_hash_table_size(first_signals) == 0) {
		signal_grabbed = FALSE;
		signal_remove("signal", (SIGNAL_FUNC) sig_signal);
	}

	if (rec->last && siglast_grabbed && g_hash_table_size(last_signals) == 0) {
		siglast_grabbed = FALSE;
		signal_remove("last signal", (SIGNAL_FUNC) sig_lastsignal);
	}

	if (strncmp(rec->signal, "command ", 8) == 0)
		command_unbind(rec->signal+8, NULL);

	g_free(rec->signal);
	g_free(rec->func);
	g_free(rec);
}

static void perl_timeout_destroy(PERL_TIMEOUT_REC *rec)
{
	perl_timeouts = g_slist_remove(perl_timeouts, rec);

	g_source_remove(rec->tag);
	g_free(rec->func);
	g_free(rec->data);
	g_free(rec);
}

static void irssi_perl_start(void)
{
	/* stolen from xchat, thanks :) */
	char *args[] = {"", "-e", "0"};
	char load_file[] =
		"sub load_file()\n"
		"{\n"
		"  (my $file_name) = @_;\n"
		"  open FH, $file_name or return \"File not found: $file_name\";\n"
		"  local($/) = undef;\n"
		"  $file = <FH>;\n"
		"  close FH;\n"
		"  eval $file;\n"
		"  eval $file if $@;\n"
		"  return $@ if $@;\n"
		"}";

	first_signals = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	last_signals = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	perl_timeouts = NULL;

	irssi_perl_interp = perl_alloc();
	perl_construct(irssi_perl_interp);

	perl_parse(irssi_perl_interp, xs_init, 3, args, NULL);
	perl_eval_pv(load_file, TRUE);
}

static void signal_destroy_hash(void *key, GSList *list)
{
	while (list != NULL) {
		PERL_SIGNAL_REC *rec = list->data;

		if (strncmp(rec->signal, "command ", 8) == 0)
			command_unbind(rec->signal+8, NULL);

		list = g_slist_remove(list, rec);

		g_free(rec->signal);
		g_free(rec->func);
		g_free(rec);
	}
}

static void irssi_perl_stop(void)
{
	g_hash_table_foreach(first_signals, (GHFunc) signal_destroy_hash, NULL);
	g_hash_table_destroy(first_signals);
	g_hash_table_foreach(last_signals, (GHFunc) signal_destroy_hash, NULL);
	g_hash_table_destroy(last_signals);
	first_signals = last_signals = NULL;

	if (signal_grabbed) {
		signal_grabbed = FALSE;
		signal_remove("signal", (SIGNAL_FUNC) sig_signal);
	}

	if (siglast_grabbed) {
		siglast_grabbed = FALSE;
		signal_remove("last signal", (SIGNAL_FUNC) sig_lastsignal);
	}

	while (perl_timeouts != NULL)
		perl_timeout_destroy(perl_timeouts->data);

	perl_destruct(irssi_perl_interp);
	perl_free(irssi_perl_interp);
	irssi_perl_interp = NULL;
}

static void cmd_run(char *data)
{
	dSP;
	struct stat statbuf;
	char *fname;
	int retcount;

	/* add .pl suffix if it's missing */
	data = (strlen(data) <= 3 || strcmp(data+strlen(data)-3, ".pl") == 0) ?
		g_strdup(data) : g_strdup_printf("%s.pl", data);

	if (g_path_is_absolute(data)) {
		/* whole path specified */
		fname = g_strdup(data);
	} else {
		/* check from ~/.irssi/scripts/ */
		fname = g_strdup_printf("%s/.irssi/scripts/%s", g_get_home_dir(), data);
		if (stat(fname, &statbuf) != 0) {
			/* check from SCRIPTDIR */
			g_free(fname),
			fname = g_strdup_printf(SCRIPTDIR"/%s", data);
		}
	}
	g_free(data);

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(fname, strlen(fname)))); g_free(fname);
	PUTBACK;

	retcount = perl_call_pv("load_file", G_EVAL|G_SCALAR);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("gui dialog", 2, "error", SvPV(ERRSV, n_a));
		(void) POPs;
	}
	else if (retcount > 0) {
		char *str = POPp;

		if (str != NULL && *str != '\0')
			signal_emit("gui dialog", 2, "error", str);
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
}

static void cmd_flush(const char *data)
{
	irssi_perl_stop();
	irssi_perl_start();
}

static int perl_signal_find(const char *signal, const char *func, int last)
{
	GHashTable *table;
        GSList *siglist;
	int signal_id;

	table = last ? last_signals : first_signals;

	signal_id = signal_get_uniq_id(signal);
        siglist = g_hash_table_lookup(table, GINT_TO_POINTER(signal_id));

	while (siglist != NULL) {
		PERL_SIGNAL_REC *rec = siglist->data;

		if (strcmp(rec->func, func) == 0)
			return TRUE;
		siglist = siglist->next;
	}

	return FALSE;
}

static void perl_signal_to(const char *signal, const char *func, int last)
{
	PERL_SIGNAL_REC *rec;
	GHashTable *table;
	GSList *siglist;
	void *signal_idp;

	if (perl_signal_find(signal, func, last))
		return;

	rec = g_new(PERL_SIGNAL_REC, 1);
	rec->signal_id = signal_get_uniq_id(signal);
	rec->signal = g_strdup(signal);
	rec->func = g_strdup(func);
	rec->last = last;

	table = last ? last_signals : first_signals;
	signal_idp = GINT_TO_POINTER(rec->signal_id);

	siglist = g_hash_table_lookup(table, signal_idp);
	if (siglist != NULL) g_hash_table_remove(table, signal_idp);

	siglist = g_slist_append(siglist, rec);
	g_hash_table_insert(table, signal_idp, siglist);

	if (!last && !signal_grabbed) {
		signal_grabbed = TRUE;
		signal_add("signal", (SIGNAL_FUNC) sig_signal);
	} else if (last && !siglast_grabbed) {
		siglast_grabbed = TRUE;
		signal_add("last signal", (SIGNAL_FUNC) sig_lastsignal);
	}
}

void perl_signal_add(const char *signal, const char *func)
{
	perl_signal_to(signal, func, FALSE);
}

void perl_signal_add_last(const char *signal, const char *func)
{
	perl_signal_to(signal, func, TRUE);
}

static void perl_signal_remove_list(GSList *list, const char *func)
{
	while (list != NULL) {
		PERL_SIGNAL_REC *rec = list->data;

		if (strcmp(func, rec->func) == 0) {
			perl_signal_destroy(rec);
			break;
		}

		list = list->next;
	}
}

void perl_signal_remove(const char *signal, const char *func)
{
	GSList *list;
	int signal_id;

	signal_id = signal_get_uniq_id(signal);

	list = g_hash_table_lookup(first_signals, GINT_TO_POINTER(signal_id));
	if (list != NULL)
		perl_signal_remove_list(list, func);
	else {
		list = g_hash_table_lookup(last_signals, GINT_TO_POINTER(signal_id));
		if (list != NULL) perl_signal_remove_list(list, func);
	}
}

static int perl_timeout(PERL_TIMEOUT_REC *rec)
{
	dSP;
	int retcount;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(rec->data, strlen(rec->data))));
	PUTBACK;

	retcount = perl_call_pv(rec->func, G_EVAL|G_SCALAR);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("perl error", 1, SvPV(ERRSV, n_a));
		(void) POPs;
	}
	else while (retcount--) (void) POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return 1;
}

int perl_timeout_add(int msecs, const char *func, const char *data)
{
	PERL_TIMEOUT_REC *rec;

	rec = g_new(PERL_TIMEOUT_REC, 1);
	rec->func = g_strdup(func);
	rec->data = g_strdup(data);
	rec->tag = g_timeout_add(msecs, (GSourceFunc) perl_timeout, rec);

	perl_timeouts = g_slist_append(perl_timeouts, rec);
	return rec->tag;
}

void perl_timeout_remove(int tag)
{
	GSList *tmp;

	for (tmp = perl_timeouts; tmp != NULL; tmp = tmp->next) {
		PERL_TIMEOUT_REC *rec = tmp->data;

		if (rec->tag == tag) {
			perl_timeout_destroy(rec);
			break;
		}
	}
}

static int call_perl(const char *func, int signal, va_list va)
{
	dSP;
	PERL_SIGNAL_ARGS_REC *rec;
	int retcount, n, ret;
	void *arg;
	HV *stash;

    /* first check if we find exact match */
    rec = NULL;
    for (n = 0; perl_signal_args[n].signal != NULL; n++)
    {
	if (signal == perl_signal_args[n].signal_id)
	{
	    rec = &perl_signal_args[n];
	    break;
	}
    }

    if (rec == NULL)
    {
	/* try to find by name */
	const char *signame;

	signame = module_find_id_str("signals", signal);
	for (n = 0; perl_signal_args[n].signal != NULL; n++)
	{
	    if (strncmp(signame, perl_signal_args[n].signal,
			strlen(perl_signal_args[n].signal)) == 0)
	    {
		rec = &perl_signal_args[n];
		break;
	    }
	}
    }

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);

    if (rec != NULL)
    {
	/* put the arguments to perl stack */
	for (n = 0; n < 7; n++)
	{
	    arg = va_arg(va, gpointer);

            if (rec->args[n] == NULL)
                break;

	    if (strcmp(rec->args[n], "string") == 0)
		XPUSHs(sv_2mortal(newSVpv(arg == NULL ? "" : arg, arg == NULL ? 0 : strlen(arg))));
	    else if (strcmp(rec->args[n], "int") == 0)
		XPUSHs(sv_2mortal(newSViv(GPOINTER_TO_INT(arg))));
	    else if (strcmp(rec->args[n], "ulongptr") == 0)
		XPUSHs(sv_2mortal(newSViv(*(gulong *) arg)));
	    else if (strncmp(rec->args[n], "glist_", 6) == 0)
	    {
		GSList *tmp;

		stash = gv_stashpv(rec->args[n]+6, 0);
		for (tmp = arg; tmp != NULL; tmp = tmp->next)
		    XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	    }
	    else
	    {
                if (arg == NULL)
			XPUSHs(sv_2mortal(newSViv(0)));
		else {
			stash = gv_stashpv(rec->args[n], 0);
			XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(arg))), stash)));
		}
	    }
	}
    }

    PUTBACK;
    retcount = perl_call_pv((char *) func, G_EVAL|G_SCALAR);
    SPAGAIN;

    ret = 0;
    if (SvTRUE(ERRSV))
    {
	STRLEN n_a;

	signal_emit("gui dialog", 2, "error", SvPV(ERRSV, n_a));
        (void)POPs;
    }
    else
    {
	SV *sv;

	if (retcount > 0)
	{
	    sv = POPs;
            if (SvIOK(sv) && SvIV(sv) == 1) ret = 1;
	}
	for (n = 2; n <= retcount; n++)
	    (void)POPi;
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return ret;
}

static void sig_signal(void *signal, ...)
{
	GSList *list;
	va_list va;

	va_start(va, signal);

	list = g_hash_table_lookup(first_signals, signal);
	while (list != NULL) {
		PERL_SIGNAL_REC *rec = list->data;

		if (call_perl(rec->func, GPOINTER_TO_INT(signal), va)) {
			signal_stop();
			return;
		}
		list = list->next;
	}

	va_end(va);
}

static void sig_lastsignal(void *signal, ...)
{
	GSList *list;
	va_list va;

	va_start(va, signal);

	list = g_hash_table_lookup(last_signals, signal);
	while (list != NULL) {
		PERL_SIGNAL_REC *rec = list->data;

		if (call_perl(rec->func, GPOINTER_TO_INT(signal), va)) {
			signal_stop();
			return;
		}
		list = list->next;
	}

	va_end(va);
}

static void irssi_perl_autorun(void)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat statbuf;
	char *path, *fname;

	path = g_strdup_printf("%s/.irssi/scripts/autorun", g_get_home_dir());
	dirp = opendir(path);
	if (dirp == NULL) {
		g_free(path);
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		fname = g_strdup_printf("%s/%s", path, dp->d_name);
                if (stat(fname, &statbuf) == 0 && !S_ISDIR(statbuf.st_mode))
			cmd_run(fname);
		g_free(fname);
	}
	closedir(dirp);
	g_free(path);
}

void irssi_perl_init(void)
{
	command_bind("run", NULL, (SIGNAL_FUNC) cmd_run);
	command_bind("perlflush", NULL, (SIGNAL_FUNC) cmd_flush);
	signal_grabbed = siglast_grabbed = FALSE;

        PL_perl_destruct_level = 1;
	irssi_perl_start();
	irssi_perl_autorun();
}

void irssi_perl_deinit(void)
{
	irssi_perl_stop();

	if (signal_grabbed) signal_remove("signal", (SIGNAL_FUNC) sig_signal);
	if (siglast_grabbed) signal_remove("last signal", (SIGNAL_FUNC) sig_lastsignal);
	command_unbind("run", (SIGNAL_FUNC) cmd_run);
	command_unbind("perlflush", (SIGNAL_FUNC) cmd_flush);
}
