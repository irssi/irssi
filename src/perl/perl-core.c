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

#define NEED_PERL_H
#define PERL_NO_GET_CONTEXT
#include "module.h"
#include "modules.h"
#include "core.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"

#include "perl-core.h"
#include "perl-common.h"
#include "perl-signals.h"
#include "perl-sources.h"

#include "XSUB.h"
#include "irssi-core.pl.h"

#ifdef TRACE_SCRIPT_UNLOADS
#define SCRIPT_UNLOAD_DEBUG g_message
#else
#define SCRIPT_UNLOAD_DEBUG while(0)g_message
#endif

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
	perl_scripts = g_slist_remove(perl_scripts, script);

	perl_signal_remove_script(script);
	perl_source_remove_script(script);

	signal_emit("script destroyed", 1, script);

	perl_script_unref(script);
}


static void perl_script_free(PERL_SCRIPT_REC *script)
{
	g_return_if_fail(script->refcount == 0);

	g_free(script->name);
	g_free(script->package);
        g_free_not_null(script->path);
        g_free_not_null(script->data);
        g_free(script);
}

extern void boot_DynaLoader(pTHX_ CV* cv);

#if PERL_STATIC_LIBS == 1
extern void boot_Irssi(pTHX_ CV *cv);

XS(boot_Irssi_Core)
{
	dXSARGS;
	PERL_UNUSED_VAR(items);

	irssi_callXS(boot_Irssi, cv, mark);
        irssi_boot(Irc);
        irssi_boot(UI);
        irssi_boot(TextUI);
	/* Make sure to keep this in line with perl_scripts_deinit below. */
	XSRETURN_YES;
}
#endif

static void xs_init(pTHX)
{
	dXSUB_SYS;

#if PERL_STATIC_LIBS == 1
	newXS("Irssi::Core::boot_Irssi_Core", boot_Irssi_Core, __FILE__);
#endif

	/* boot the dynaloader too, if we want to use some
	   other dynamic modules.. */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);
}

/* Initialize perl interpreter */
void perl_scripts_init(void)
{
	char *code, *use_code;

	perl_scripts = NULL;
        perl_sources_start();
	perl_signals_start();

	my_perl = perl_alloc();
	perl_construct(my_perl);

	perl_parse(my_perl, xs_init, G_N_ELEMENTS(perl_args)-1, perl_args, NULL);
#if PERL_STATIC_LIBS == 1
	perl_eval_pv("Irssi::Core::->boot_Irssi_Core(0.9);", TRUE);
#endif

        perl_common_start();

	use_code = perl_get_use_list();
        code = g_strdup_printf(irssi_core_code, PERL_STATIC_LIBS, use_code);
	perl_eval_pv(code, TRUE);

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

#if PERL_STATIC_LIBS == 1
	/* If perl is statically built we should manually deinit the modules
	   which are booted in boot_Irssi_Core above */
	perl_eval_pv("foreach my $lib (qw("
		"Irssi" " "
		"Irssi::Irc" " "
		"Irssi::UI" " "
		"Irssi::TextUI"
		")) { eval $lib . '::deinit();'; }", TRUE);
#endif

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

	ret = name->str;
        g_string_free(name, FALSE);
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
			perl_script_error(script, error);
			g_free(error);
		}
	}

	FREETMPS;
	LEAVE;

        return (!script->destroyed);
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
	script->destroyed = FALSE;
	script->disable_signals = -1;
	/* two references: one for the script itself, one for our caller */
	script->refcount = 2;

	perl_scripts = g_slist_append(perl_scripts, script);
	signal_emit("script created", 1, script);

	if (!perl_script_eval(script)) {
		perl_script_unref(script);
                script = NULL; /* the script is destroyed in "script error" signal */
	}
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
        g_return_if_fail(script != NULL);

	g_return_if_fail(script->refcount > 0);

	if (script->destroyed)
		return;

	script->destroyed = 1;

	perl_script_destroy_package(script);
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
			perl_script_unref(perl_script_load_file(fname));
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

int perl_script_ref(PERL_SCRIPT_REC *script)
{
	g_return_val_if_fail(script != NULL, FALSE);
	g_return_val_if_fail(script->refcount > 0, FALSE);

	/* If the script's been destroyed, there's no point calling into it. */

	if (script->destroyed) {
		g_warning("rejecting attempt to reference destroyed script %p (%s)\n", script, script->name);
		return FALSE;
	}

	if (++script->refcount == UINT8_MAX) {
		--script->refcount;
		/* something is almost certainly wrong here. */
		/* Report an error; that'll most likely cause the offending script to be unloaded. */
		perl_script_error(script, "Too much signal/command recursion");
		return FALSE;
	}

	SCRIPT_UNLOAD_DEBUG("reference count for %p (%s) is now %d\n", script, script->name, script->refcount);
	return TRUE;
}

void perl_script_unref(PERL_SCRIPT_REC *script)
{
	/* this makes it easier to use perl_load_script_data() and perl_load_script_file() */
	if (script == NULL)
		return;

	g_return_if_fail(script->refcount > 0);

	if (--script->refcount == 0) {
		SCRIPT_UNLOAD_DEBUG("freeing script %p (%s)\n", script, script->name);
		perl_script_free(script);
	} else {
		SCRIPT_UNLOAD_DEBUG("not freeing script %p (%s); refcount is now %d\n",
			script, script->name, script->refcount);
	}
}

void perl_script_error(PERL_SCRIPT_REC *script, const char *error)
{
	g_return_if_fail(script != NULL);
	g_return_if_fail(script->refcount > 0);

	/* Don't bother reporting errors in destroyed scripts */
	if (script->destroyed) {
		SCRIPT_UNLOAD_DEBUG("suppressing script error notification for destroyed script");
		return;
	}

	if (++script->disable_signals > 0) {
		g_warning("Recursive error detected in script %s", script->name);
	}

	signal_emit("script error", 2, script, error);

	--script->disable_signals;
}
