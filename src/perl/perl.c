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

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"

#include "fe-common/core/themes.h"
#include "fe-common/core/formats.h"

#include "perl-common.h"
#include "perl-signals.h"

/* For compatibility with perl 5.004 and older */
#ifndef HAVE_PL_PERL
#  define PL_perl_destruct_level perl_destruct_level
#endif

extern void xs_init(void);

typedef struct {
	int tag;
	char *func;
	char *data;
} PERL_SOURCE_REC;

static GSList *perl_sources;
static GSList *perl_scripts;
static PerlInterpreter *irssi_perl_interp;

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

        perl_signals_start();
	perl_sources = NULL;

	irssi_perl_interp = perl_alloc();
	perl_construct(irssi_perl_interp);

	perl_parse(irssi_perl_interp, xs_init, 3, args, NULL);
	perl_eval_pv(eval_file_code, TRUE);

        perl_common_init();
}

static void perl_unregister_theme(const char *package)
{
	FORMAT_REC *formats;
	int n;

	formats = g_hash_table_lookup(default_formats, package);
	if (formats == NULL) return;

	for (n = 0; formats[n].def != NULL; n++) {
		g_free(formats[n].tag);
		g_free(formats[n].def);
	}
	g_free(formats);
	theme_unregister_module(package);
}

static int perl_script_destroy(const char *name)
{
	GSList *tmp, *next, *item;
	char *package;
	int package_len;

	item = gslist_find_string(perl_scripts, name);
	if (item == NULL) return FALSE;

	package = g_strdup_printf("Irssi::Script::%s", name);
	package_len = strlen(package);

        perl_signals_package_destroy(package);

	/* timeouts and input waits */
	for (tmp = perl_sources; tmp != NULL; tmp = next) {
		PERL_SOURCE_REC *rec = tmp->data;

		next = tmp->next;
		if (strncmp(rec->func, package, package_len) == 0)
			perl_source_destroy(rec);
	}

	/* theme */
	perl_unregister_theme(package);

	g_free(package);
	g_free(item->data);
	perl_scripts = g_slist_remove(perl_scripts, item->data);
	return TRUE;
}

static void irssi_perl_stop(void)
{
	GSList *tmp;
	char *package;

        perl_signals_stop();

	/* timeouts and input waits */
	while (perl_sources != NULL)
		perl_source_destroy(perl_sources->data);

	/* themes */
	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		package = g_strdup_printf("Irssi::Script::%s",
					  (char *) tmp->data);
		perl_unregister_theme(package);
		g_free(package);
	}

	/* scripts list */
	g_slist_foreach(perl_scripts, (GFunc) g_free, NULL);
	g_slist_free(perl_scripts);
	perl_scripts = NULL;

	/* perl-common stuff */
        perl_common_deinit();

	/* perl interpreter */
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
	XPUSHs(sv_2mortal(new_pv(fname))); g_free(fname);
	XPUSHs(sv_2mortal(new_pv(name))); g_free(name);
	PUTBACK;

	retcount = perl_call_pv("Irssi::Load::eval_file",
				G_EVAL|G_SCALAR);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("gui dialog", 2, "error", SvPV(ERRSV, n_a));
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

static void cmd_perl(const char *data)
{
	dSP;
	GString *code;
	char *uses;
        SV *sv;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);

	code = g_string_new(NULL);

	uses = perl_get_use_list();
	g_string_sprintf(code, "sub { use Irssi;%s\n%s }", uses, data);

	sv = perl_eval_pv(code->str, TRUE);
	perl_call_sv(sv, G_VOID|G_NOARGS|G_EVAL|G_DISCARD);

        g_free(uses);
	g_string_free(code, TRUE);

	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("gui dialog", 2, "error", SvPV(ERRSV, n_a));
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

static int perl_source_event(PERL_SOURCE_REC *rec)
{
	dSP;
	int retcount;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(new_pv(rec->data)));
	PUTBACK;

	retcount = perl_call_pv(rec->func, G_EVAL|G_SCALAR);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("perl error", 1, SvPV(ERRSV, n_a));
	}

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
        GIOChannel *channel;

	rec = g_new(PERL_SOURCE_REC, 1);
	rec->func = g_strdup_printf("%s::%s", perl_get_package(), func);
	rec->data = g_strdup(data);

        channel = g_io_channel_unix_new(source);
	rec->tag = g_input_add(channel, condition,
			       (GInputFunction) perl_source_event, rec);
	g_io_channel_unref(channel);

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
	command_bind("perl", NULL, (SIGNAL_FUNC) cmd_perl);
	command_bind("perlflush", NULL, (SIGNAL_FUNC) cmd_perlflush);

	PL_perl_destruct_level = 1;
	perl_signals_init();
	irssi_perl_start();
	irssi_perl_autorun();
}

void perl_deinit(void)
{
	perl_signals_deinit();
	irssi_perl_stop();

	command_unbind("run", (SIGNAL_FUNC) cmd_run);
	command_unbind("unload", (SIGNAL_FUNC) cmd_unload);
	command_unbind("perl", (SIGNAL_FUNC) cmd_perl);
	command_unbind("perlflush", (SIGNAL_FUNC) cmd_perlflush);
}
