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
#include "misc.h"
#include "perl-common.h"
#include "servers.h"

/* For compatibility with perl 5.004 and older */
#ifndef ERRSV
#  define ERRSV GvSV(errgv)
#endif

#ifndef HAVE_PL_PERL
#  define PL_perl_destruct_level perl_destruct_level
#endif

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
} PERL_SOURCE_REC;

#include "perl-signals.h"

static GHashTable *first_signals, *last_signals;
static GSList *perl_sources;
static GSList *perl_scripts;
static PerlInterpreter *irssi_perl_interp;
static int signal_grabbed, siglast_grabbed;

static void sig_signal(void *signal, ...);
static void sig_lastsignal(void *signal, ...);

static void perl_signal_destroy(PERL_SIGNAL_REC *rec)
{
	GHashTable *table;
	GSList **siglist;
	void *signal_idp;

	g_return_if_fail(rec != NULL);

	table = rec->last ? last_signals : first_signals;
	signal_idp = GINT_TO_POINTER(rec->signal_id);

	siglist = g_hash_table_lookup(table, signal_idp);
	if (siglist == NULL) return;

	*siglist = g_slist_remove(*siglist, rec);
	if (*siglist == NULL) {
		g_free(siglist);
		g_hash_table_remove(table, signal_idp);
	}

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

static void perl_source_destroy(PERL_SOURCE_REC *rec)
{
	perl_sources = g_slist_remove(perl_sources, rec);

	g_source_remove(rec->tag);
	g_free(rec->func);
	g_free(rec->data);
	g_free(rec);
}

static void irssi_perl_start(void)
{
	char *args[] = {"", "-e", "0"};
	char eval_file_code[] =
		"package Irssi::Load;\n"
		"\n"
		"use Symbol qw(delete_package);\n"
		"\n"
		"sub eval_file {\n"
		"  my ($filename, $id) = @_;\n"
		"  my $package = \"Irssi::Script::$id\";\n"
		"  delete_package($package);\n"
		"\n"
		"  local *FH;\n"
		"  open FH, $filename or die \"File not found: $filename\";\n"
		"  local($/) = undef;\n"
		"  my $sub = <FH>;\n"
		"  close FH;\n"
		"\n"
		"  my $eval = qq{package $package; sub handler { $sub; }};\n"
		"  {\n"
		"      # hide our variables within this block\n"
		"      my ($filename, $package, $sub);\n"
		"      eval $eval;\n"
		"  }\n"
		"  die $@ if $@;\n"
		"\n"
		"  eval {$package->handler;};\n"
		"  die $@ if $@;\n"
		"}\n";

	first_signals = g_hash_table_new((GHashFunc) g_direct_hash,
					 (GCompareFunc) g_direct_equal);
	last_signals = g_hash_table_new((GHashFunc) g_direct_hash,
					(GCompareFunc) g_direct_equal);
	perl_sources = NULL;

	irssi_perl_interp = perl_alloc();
	perl_construct(irssi_perl_interp);

	perl_parse(irssi_perl_interp, xs_init, 3, args, NULL);
	perl_eval_pv(eval_file_code, TRUE);
}

static int signal_destroy_hash(void *key, GSList **list, const char *package)
{
	GSList *tmp, *next;
	int len;

	len = package == NULL ? 0 : strlen(package);
	for (tmp = *list; tmp != NULL; tmp = next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		next = tmp->next;
		if (package != NULL && strncmp(rec->func, package, len) != 0)
                        continue;

		if (strncmp(rec->signal, "command ", 8) == 0)
			command_unbind(rec->signal+8, NULL);

		*list = g_slist_remove(*list, rec);

		g_free(rec->signal);
		g_free(rec->func);
		g_free(rec);
	}

	if (*list != NULL)
		return FALSE;

	g_free(list);
	return TRUE;
}

static int perl_script_destroy(const char *name)
{
	GSList *tmp, *next;
	char *package;
	int package_len;

	if (gslist_find_string(perl_scripts, name) == NULL)
		return FALSE;

	package = g_strdup_printf("Irssi::Script::%s::", name);
	package_len = strlen(package);

	g_hash_table_foreach_remove(first_signals,
				    (GHRFunc) signal_destroy_hash, package);
	g_hash_table_foreach_remove(last_signals,
				    (GHRFunc) signal_destroy_hash, package);

	for (tmp = perl_sources; tmp != NULL; tmp = next) {
		PERL_SOURCE_REC *rec = tmp->data;

		next = tmp->next;
		if (strncmp(rec->func, package, package_len) == 0)
			perl_source_destroy(rec);
	}

	g_free(package);
	return TRUE;
}

static void irssi_perl_stop(void)
{
	g_hash_table_foreach(first_signals,
			     (GHFunc) signal_destroy_hash, NULL);
	g_hash_table_destroy(first_signals);
	g_hash_table_foreach(last_signals,
			     (GHFunc) signal_destroy_hash, NULL);
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

	while (perl_sources != NULL)
		perl_source_destroy(perl_sources->data);

	g_slist_foreach(perl_scripts, (GFunc) g_free, NULL);
	g_slist_free(perl_scripts);
	perl_scripts = NULL;

	perl_destruct(irssi_perl_interp);
	perl_free(irssi_perl_interp);
	irssi_perl_interp = NULL;
}

static void script_fix_name(char *name)
{
	while (*name != '\0') {
		if (*name != '_' && !isalnum(*name))
			*name = '_';
		name++;
	}
}

static void cmd_run(const char *data)
{
	dSP;
	struct stat statbuf;
	char *fname, *name, *p;
	int retcount;

	if (g_path_is_absolute(data)) {
		/* whole path specified */
		fname = g_strdup(data);
	} else {
		/* add .pl suffix if it's missing */
		name = (strlen(data) > 3 && strcmp(data+strlen(data)-3, ".pl") == 0) ?
			g_strdup(data) : g_strdup_printf("%s.pl", data);

		/* check from ~/.irssi/scripts/ */
		fname = g_strdup_printf("%s/.irssi/scripts/%s", g_get_home_dir(), name);
		if (stat(fname, &statbuf) != 0) {
			/* check from SCRIPTDIR */
			g_free(fname),
			fname = g_strdup_printf(SCRIPTDIR"/%s", name);
		}
		g_free(name);
	}

	/* get script name */
	name = g_strdup(g_basename(fname));
	p = strrchr(name, '.');
	if (p != NULL) *p = '\0';

	script_fix_name(name);
	perl_script_destroy(name);
	perl_scripts = g_slist_append(perl_scripts, g_strdup(name));

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(fname, strlen(fname)))); g_free(fname);
	XPUSHs(sv_2mortal(newSVpv(name, strlen(name)))); g_free(name);
	PUTBACK;

	retcount = perl_call_pv("Irssi::Load::eval_file",
				G_EVAL|G_SCALAR);
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

static void cmd_unload(const char *data)
{
	char *name;

	name = g_strdup(data);
	script_fix_name(name);
	if (perl_script_destroy(name))
		signal_stop();
	g_free(name);
}

static void cmd_perlflush(const char *data)
{
	irssi_perl_stop();
	irssi_perl_start();
}

/* returns the package who called us */
static char *perl_get_package(void)
{
	STRLEN n_a;

	perl_eval_pv("($package) = caller;", TRUE);
	return SvPV(perl_get_sv("package", FALSE), n_a);
}

static void perl_signal_to(const char *signal, const char *func, int last)
{
	PERL_SIGNAL_REC *rec;
	GHashTable *table;
	GSList **siglist;
	void *signal_idp;

	rec = g_new(PERL_SIGNAL_REC, 1);
	rec->signal_id = signal_get_uniq_id(signal);
	rec->signal = g_strdup(signal);
	rec->func = g_strdup_printf("%s::%s", perl_get_package(), func);
	rec->last = last;

	table = last ? last_signals : first_signals;
	signal_idp = GINT_TO_POINTER(rec->signal_id);

	siglist = g_hash_table_lookup(table, signal_idp);
	if (siglist == NULL) {
		siglist = g_new0(GSList *, 1);
		g_hash_table_insert(table, signal_idp, siglist);
	}

	*siglist = g_slist_append(*siglist, rec);

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

static void perl_signal_remove_list(GSList **list, const char *func)
{
	GSList *tmp;

	g_return_if_fail(list != NULL);

	for (tmp = *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (strcmp(func, rec->func) == 0) {
			perl_signal_destroy(rec);
			break;
		}
	}
}

void perl_signal_remove(const char *signal, const char *func)
{
	GSList **list;
	char *fullfunc;
	int signal_id;

	signal_id = signal_get_uniq_id(signal);

	fullfunc = g_strdup_printf("%s::%s", perl_get_package(), func);
	list = g_hash_table_lookup(first_signals, GINT_TO_POINTER(signal_id));
	if (list != NULL)
		perl_signal_remove_list(list, func);
	else {
		list = g_hash_table_lookup(last_signals, GINT_TO_POINTER(signal_id));
		if (list != NULL) perl_signal_remove_list(list, func);
	}
	g_free(fullfunc);
}

static int perl_source_event(PERL_SOURCE_REC *rec)
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
	PERL_SOURCE_REC *rec;

	rec = g_new(PERL_SOURCE_REC, 1);
	rec->func = g_strdup_printf("%s::%s", perl_get_package(), func);
	rec->data = g_strdup(data);
	rec->tag = g_timeout_add(msecs, (GSourceFunc) perl_source_event, rec);

	perl_sources = g_slist_append(perl_sources, rec);
	return rec->tag;
}

int perl_input_add(int source, int condition,
		   const char *func, const char *data)
{
	PERL_SOURCE_REC *rec;

	rec = g_new(PERL_SOURCE_REC, 1);
	rec->func = g_strdup_printf("%s::%s", perl_get_package(), func);
	rec->data = g_strdup(data);
	rec->tag = g_input_add(source, condition,
			       (GInputFunction) perl_source_event, rec);

	perl_sources = g_slist_append(perl_sources, rec);
	return rec->tag;
}

void perl_source_remove(int tag)
{
	GSList *tmp;

	for (tmp = perl_sources; tmp != NULL; tmp = tmp->next) {
		PERL_SOURCE_REC *rec = tmp->data;

		if (rec->tag == tag) {
			perl_source_destroy(rec);
			break;
		}
	}
}

static PERL_SIGNAL_ARGS_REC *perl_signal_find(int signal)
{
	const char *signame;
	int n;

	for (n = 0; perl_signal_args[n].signal != NULL; n++) {
		if (signal == perl_signal_args[n].signal_id)
			return &perl_signal_args[n];
	}

	/* try to find by name */
	signame = module_find_id_str("signals", signal);
	for (n = 0; perl_signal_args[n].signal != NULL; n++) {
		if (strncmp(signame, perl_signal_args[n].signal,
			    strlen(perl_signal_args[n].signal)) == 0)
			return &perl_signal_args[n];
	}

	return NULL;
}


static int call_perl(const char *func, int signal, va_list va)
{
	dSP;
	PERL_SIGNAL_ARGS_REC *rec;
	int retcount, ret;

	HV *stash;
	void *arg;
	int n;

	/* first check if we find exact match */
	rec = perl_signal_find(signal);

	ENTER;
	SAVETMPS;

	PUSHMARK(sp);

	if (rec != NULL) {
		/* push the arguments to perl stack */
		for (n = 0; n < 7 && rec->args[n] != NULL; n++) {
			arg = va_arg(va, void *);

			if (strcmp(rec->args[n], "string") == 0)
				XPUSHs(sv_2mortal(new_pv(arg)));
			else if (strcmp(rec->args[n], "int") == 0)
				XPUSHs(sv_2mortal(newSViv(GPOINTER_TO_INT(arg))));
			else if (strcmp(rec->args[n], "ulongptr") == 0)
				XPUSHs(sv_2mortal(newSViv(*(unsigned long *) arg)));
			else if (strncmp(rec->args[n], "gslist_", 7) == 0) {
				/* linked list - push as AV */
				GSList *tmp;
				AV *av;

				av = newAV();
				stash = gv_stashpv(rec->args[n]+7, 0);
				for (tmp = arg; tmp != NULL; tmp = tmp->next)
					av_push(av, sv_2mortal(new_bless(tmp->data, stash)));
				XPUSHs(newRV_noinc((SV*)av));
			} else if (arg == NULL) {
				/* don't bless NULL arguments */
				XPUSHs(sv_2mortal(newSViv(0)));
			} else if (strcmp(rec->args[n], "iobject") == 0) {
				/* "irssi object" - any struct that has
				   "int type; int chat_type" as its first
				   variables (server, channel, ..) */
				stash = irssi_get_stash((SERVER_REC *) arg);
				XPUSHs(sv_2mortal(new_bless(arg, stash)));
			} else {
				/* blessed object */
				stash = gv_stashpv(rec->args[n], 0);
				XPUSHs(sv_2mortal(new_bless(arg, stash)));
			}
		}
	}

	PUTBACK;
	retcount = perl_call_pv((char *) func, G_EVAL|G_SCALAR);
	SPAGAIN;

	ret = 0;
	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("gui dialog", 2, "error", SvPV(ERRSV, n_a));
		(void)POPs;
	} else if (retcount > 0) {
		SV *sv = POPs;

		if (SvIOK(sv) && SvIV(sv) == 1) ret = 1;
		while (--retcount > 0)
			(void)POPi;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret;
}

static void sig_signal(void *signal, ...)
{
	GSList **list, *tmp;
	va_list va;

	va_start(va, signal);

	list = g_hash_table_lookup(first_signals, signal);
	for (tmp = list == NULL ? NULL : *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (call_perl(rec->func, GPOINTER_TO_INT(signal), va)) {
			signal_stop();
			break;
		}
	}

	va_end(va);
}

static void sig_lastsignal(void *signal, ...)
{
	GSList **list, *tmp;
	va_list va;

	va_start(va, signal);

	list = g_hash_table_lookup(last_signals, signal);
	for (tmp = list == NULL ? NULL : *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (call_perl(rec->func, GPOINTER_TO_INT(signal), va)) {
			signal_stop();
			break;
		}
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

void perl_init(void)
{
	perl_scripts = NULL;
	command_bind("run", NULL, (SIGNAL_FUNC) cmd_run);
	command_bind_first("unload", NULL, (SIGNAL_FUNC) cmd_unload);
	command_bind("perlflush", NULL, (SIGNAL_FUNC) cmd_perlflush);
	signal_grabbed = siglast_grabbed = FALSE;

        PL_perl_destruct_level = 1;
	irssi_perl_start();

	perl_common_init();
	irssi_perl_autorun();
}

void perl_deinit(void)
{
	irssi_perl_stop();
	perl_common_deinit();

	if (signal_grabbed) signal_remove("signal", (SIGNAL_FUNC) sig_signal);
	if (siglast_grabbed) signal_remove("last signal", (SIGNAL_FUNC) sig_lastsignal);
	command_unbind("run", (SIGNAL_FUNC) cmd_run);
	command_unbind("unload", (SIGNAL_FUNC) cmd_unload);
	command_unbind("perlflush", (SIGNAL_FUNC) cmd_perlflush);
}
