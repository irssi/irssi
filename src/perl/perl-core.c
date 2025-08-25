/*
 perl-core.c : irssi

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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <wchar.h>

#define NEED_PERL_H
#define PERL_NO_GET_CONTEXT
#include "module.h"
#include <irssi/src/core/modules.h>
#include <irssi/src/core/core.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/perl/perl-core.h>
#include <irssi/src/perl/perl-common.h>
#include <irssi/src/perl/perl-signals.h>
#include <irssi/src/perl/perl-sources.h>

#include "XSUB.h"
#include "irssi-core.pl.h"

extern char **environ;

GSList *perl_scripts;
PerlInterpreter *my_perl;

static int print_script_errors;
static char *perl_args[] = {"", "-e", "0", NULL};

#define IS_PERL_SCRIPT(file) \
	(strlen(file) > 3 && g_strcmp0(file+strlen(file)-3, ".pl") == 0)

static void perl_script_destroy_package(PERL_SCRIPT_REC *script)
{
	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(new_pv(script->package)));
	PUTBACK;

	perl_call_pv("Irssi::Core::destroy", G_VOID|G_EVAL|G_DISCARD);

	FREETMPS;
	LEAVE;
}

static void perl_script_destroy(PERL_SCRIPT_REC *script)
{

	signal_emit("script destroyed", 1, script);

	g_free(script->name);
	g_free(script->package);
        g_free_not_null(script->path);
        g_free_not_null(script->data);
        g_free(script);
}

extern void boot_DynaLoader(pTHX_ CV* cv);

static void xs_init(pTHX)
{
	dXSUB_SYS;

	/* boot the dynaloader too, if we want to use some
	   other dynamic modules.. */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);
}

/* Initialize perl interpreter */
void perl_scripts_init(void)
{
	char *code, *use_code;
	int broken_perl;

	perl_scripts = NULL;
        perl_sources_start();
	perl_signals_start();

	my_perl = perl_alloc();
	broken_perl = wcwidth(160);
	perl_construct(my_perl);
	broken_perl = broken_perl != wcwidth(160);

	perl_parse(my_perl, xs_init, G_N_ELEMENTS(perl_args) - 1, perl_args, NULL);

	perl_common_start();

	use_code = perl_get_use_list();
	code = g_strdup_printf(irssi_core_code, use_code);
	perl_eval_pv(code, TRUE);
	if (broken_perl) {
		g_warning("applying locale workaround for Perl %d.%d, see "
		          "https://github.com/Perl/perl5/issues/21366",
		          PERL_REVISION, PERL_VERSION);
		perl_eval_pv("package Irssi::Core;"
		             /* https://github.com/Perl/perl5/issues/21746 */
		             "if ( $] == $] )"
		             "{"
		             "require POSIX;"
		             "POSIX::setlocale(&POSIX::LC_ALL, \"\");"
		             "}"
		             "1;",
		             TRUE);
	}

	g_free(code);
	g_free(use_code);
}

/* Destroy all perl scripts and deinitialize perl interpreter */
void perl_scripts_deinit(void)
{
	if (my_perl == NULL)
		return;

	/* unload all scripts */
        while (perl_scripts != NULL)
		perl_script_unload(perl_scripts->data);

        signal_emit("perl scripts deinit", 0);

        perl_signals_stop();
	perl_sources_stop();
	perl_common_stop();

	/* Unload all perl libraries loaded with dynaloader */
	perl_eval_pv("foreach my $lib (@DynaLoader::dl_modules) { if ($lib =~ /^Irssi\\b/) { $lib .= '::deinit();'; eval $lib; } }", TRUE);

	/* We could unload all libraries .. but this crashes with some
	   libraries, probably because we don't call some deinit function..
	   Anyway, this would free some memory with /SCRIPT RESET, but it
	   leaks memory anyway. */
	/*perl_eval_pv("eval { foreach my $lib (@DynaLoader::dl_librefs) { DynaLoader::dl_unload_file($lib); } }", TRUE);*/

	/* perl interpreter */
	PL_perl_destruct_level = 1;
	perl_destruct(my_perl);
	perl_free(my_perl);
	my_perl = NULL;
}

/* Modify the script name so that all non-alphanumeric characters are
   translated to '_' */
void script_fix_name(char *name)
{
	char *p;

	p = strrchr(name, '.');
	if (p != NULL) *p = '\0';

	while (*name != '\0') {
		if (*name != '_' && !i_isalnum(*name))
			*name = '_';
		name++;
	}
}

static char *script_file_get_name(const char *path)
{
	char *name;

        name = g_path_get_basename(path);
	script_fix_name(name);
        return name;
}

static char *script_data_get_name(void)
{
	GString *name;
        char *ret;
	int n;

	name = g_string_new(NULL);
        n = 1;
	do {
		g_string_printf(name, "data%d", n);
                n++;
	} while (perl_script_find(name->str) != NULL);

	ret = g_string_free_and_steal(name);
	return ret;
}

static int perl_script_eval(PERL_SCRIPT_REC *script)
{
	dSP;
	char *error;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(new_pv(script->path != NULL ? script->path :
				 script->data)));
	XPUSHs(sv_2mortal(new_pv(script->name)));
	PUTBACK;

	perl_call_pv(script->path != NULL ?
                              "Irssi::Core::eval_file" :
                              "Irssi::Core::eval_data",
                              G_EVAL|G_DISCARD);
	SPAGAIN;

        error = NULL;
	if (SvTRUE(ERRSV)) {
		error = SvPV_nolen(ERRSV);

		if (error != NULL) {
			error = g_strdup(error);
			signal_emit("script error", 2, script, error);
			g_free(error);
		}
	}

	FREETMPS;
	LEAVE;

        return error == NULL;
}

/* NOTE: name must not be free'd */
static PERL_SCRIPT_REC *script_load(char *name, const char *path,
				    const char *data)
{
        PERL_SCRIPT_REC *script;

	/* if there's a script with a same name, destroy it */
	script = perl_script_find(name);
	if (script != NULL)
		perl_script_unload(script);

	script = g_new0(PERL_SCRIPT_REC, 1);
	script->name = name;
	script->package = g_strdup_printf("Irssi::Script::%s", name);
	script->path = g_strdup(path);
        script->data = g_strdup(data);
	script->refcount = 1;

	perl_scripts = g_slist_append(perl_scripts, script);
	signal_emit("script created", 1, script);

	if (!perl_script_eval(script))
                script = NULL; /* the script is destroyed in "script error" signal */
        return script;
}

/* Load a perl script, path must be a full path. */
PERL_SCRIPT_REC *perl_script_load_file(const char *path)
{
	char *name;

        g_return_val_if_fail(path != NULL, NULL);

        name = script_file_get_name(path);
        return script_load(name, path, NULL);
}

/* Load a perl script from given data */
PERL_SCRIPT_REC *perl_script_load_data(const char *data)
{
	char *name;

        g_return_val_if_fail(data != NULL, NULL);

	name = script_data_get_name();
	return script_load(name, NULL, data);
}

/* Unload perl script */
void perl_script_unload(PERL_SCRIPT_REC *script)
{
	GSList *link;
	g_return_if_fail(script != NULL);

	perl_script_destroy_package(script);

	perl_signal_remove_script(script);
	perl_source_remove_script(script);

	link = g_slist_find(perl_scripts, script);
	if (link != NULL) {
		perl_scripts = g_slist_remove_link(perl_scripts, link);
		g_slist_free(link);
		perl_script_unref(script);
	}
}

/* Enter a perl script (signal or input source) */
void perl_script_ref(PERL_SCRIPT_REC *script)
{
	g_return_if_fail(script != NULL);

	script->refcount++;
}

void perl_script_unref(PERL_SCRIPT_REC *script)
{
	g_return_if_fail(script != NULL);

	script->refcount--;
	if (!script->refcount)
		perl_script_destroy(script);
}

/* Find loaded script by name */
PERL_SCRIPT_REC *perl_script_find(const char *name)
{
	GSList *tmp;

        g_return_val_if_fail(name != NULL, NULL);

	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		PERL_SCRIPT_REC *rec = tmp->data;

		if (g_strcmp0(rec->name, name) == 0)
                        return rec;
	}

        return NULL;
}

/* Find loaded script by package */
PERL_SCRIPT_REC *perl_script_find_package(const char *package)
{
	GSList *tmp;

        g_return_val_if_fail(package != NULL, NULL);

	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		PERL_SCRIPT_REC *rec = tmp->data;

		if (g_strcmp0(rec->package, package) == 0)
                        return rec;
	}

        return NULL;
}

/* Returns full path for the script */
char *perl_script_get_path(const char *name)
{
	struct stat statbuf;
	char *file, *path;

	if (g_path_is_absolute(name) || (name[0] == '~' && name[1] == '/')) {
		/* full path specified */
                return convert_home(name);
	}

	/* add .pl suffix if it's missing */
	file = IS_PERL_SCRIPT(name) ? g_strdup(name) :
		g_strdup_printf("%s.pl", name);

	/* check from ~/.irssi/scripts/ */
	path = g_strdup_printf("%s/scripts/%s", get_irssi_dir(), file);
	if (stat(path, &statbuf) != 0) {
		/* check from SCRIPTDIR */
		g_free(path);
		path = g_strdup_printf(SCRIPTDIR"/%s", file);
		if (stat(path, &statbuf) != 0) {
			g_free(path);
			path = NULL;
		}
	}
	g_free(file);
	return path;
}

/* If core should handle printing script errors */
void perl_core_print_script_error(int print)
{
        print_script_errors = print;
}

/* Returns the perl module's API version. */
int perl_get_api_version(void)
{
        return IRSSI_PERL_API_VERSION;
}

void perl_scripts_autorun(void)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat statbuf;
	char *path, *fname;

        /* run *.pl scripts from ~/.irssi/scripts/autorun/ */
	path = g_strdup_printf("%s/scripts/autorun", get_irssi_dir());
	dirp = opendir(path);
	if (dirp == NULL) {
		g_free(path);
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (!IS_PERL_SCRIPT(dp->d_name))
			continue;

		fname = g_strdup_printf("%s/%s", path, dp->d_name);
		if (stat(fname, &statbuf) == 0 && !S_ISDIR(statbuf.st_mode))
			perl_script_load_file(fname);
		g_free(fname);
	}
	closedir(dirp);
	g_free(path);
}

static void sig_script_error(PERL_SCRIPT_REC *script, const char *error)
{
	char *str;

	if (print_script_errors) {
		str = g_strdup_printf("Script '%s' error:",
				      script == NULL ? "??" : script->name);
		signal_emit("gui dialog", 2, "error", str);
		signal_emit("gui dialog", 2, "error", error);
                g_free(str);
	}

	if (script != NULL) {
		perl_script_unload(script);
                signal_stop();
	}
}

static void sig_autorun(void)
{
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_autorun);

        perl_scripts_autorun();
}

void perl_core_init(void)
{
	int argc = G_N_ELEMENTS(perl_args);
	char **argv = perl_args;

	PERL_SYS_INIT3(&argc, &argv, &environ);
	print_script_errors = 1;
	settings_add_str("perl", "perl_use_lib", PERL_USE_LIB);

	/*PL_perl_destruct_level = 1; - this crashes with some people.. */
	perl_signals_init();
        signal_add_last("script error", (SIGNAL_FUNC) sig_script_error);

	perl_scripts_init();

	if (irssi_init_finished)
		perl_scripts_autorun();
	else {
		signal_add("irssi init finished", (SIGNAL_FUNC) sig_autorun);
		settings_check();
	}

	module_register("perl", "core");
}

void perl_core_deinit(void)
{
        perl_scripts_deinit();
	perl_signals_deinit();

	signal_remove("script error", (SIGNAL_FUNC) sig_script_error);
	PERL_SYS_TERM();
}

void perl_core_abicheck(int *version)
{
	*version = IRSSI_ABI_VERSION;
}
