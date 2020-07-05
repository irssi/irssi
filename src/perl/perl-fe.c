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

#include <irssi/src/perl/module-fe.h>
#include <irssi/src/core/modules.h>
#include <irssi/src/perl/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>

#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/completion.h>

#include <irssi/src/perl/perl-core.h>

static void cmd_script(const char *data, SERVER_REC *server, void *item)
{
	if (*data == '\0')
                data = "list";

	command_runsub("script", data, server, item);
}

static void cmd_script_exec(const char *data)
{
        PERL_SCRIPT_REC *script;
	GHashTable *optlist;
	char *code;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST,
			    "script exec", &optlist, &code))
		return;

        if (*code == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

        script = perl_script_load_data(code);
	if (script != NULL &&
	    g_hash_table_lookup(optlist, "permanent") == NULL) {
		/* not a permanent script, unload immediately */
                perl_script_unload(script);
	}


	cmd_params_free(free_arg);
}

static void cmd_script_load(const char *data)
{
        PERL_SCRIPT_REC *script;
	char *fname, *path;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &path))
		return;

        if (*path == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	fname = perl_script_get_path(path);
	if (fname == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
                            TXT_SCRIPT_NOT_FOUND, data);
	} else {
		script = perl_script_load_file(fname);
		if (script != NULL) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
				    TXT_SCRIPT_LOADED,
				    script->name, script->path);
		}
		g_free(fname);
	}
	cmd_params_free(free_arg);
}

static void cmd_script_unload(const char *data)
{
	PERL_SCRIPT_REC *script;
        char *name;
	void *free_arg;

	if (!cmd_get_params(data, &free_arg, 1, &name))
		return;

        if (*name == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

        script_fix_name(name);
	script = perl_script_find(name);
	if (script == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
                            TXT_SCRIPT_NOT_LOADED, name);
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_SCRIPT_UNLOADED, script->name);
		perl_script_unload(script);
	}
	cmd_params_free(free_arg);
}

static void cmd_script_reset(const char *data)
{
	void *free_arg;
	GHashTable *optlist;

	if (!cmd_get_params(data, &free_arg, 0 | PARAM_FLAG_OPTIONS,
			    "script reset", &optlist))
		return;

	perl_scripts_deinit();
	perl_scripts_init();

	if (g_hash_table_lookup(optlist, "autorun") != NULL)
		perl_scripts_autorun();

	cmd_params_free(free_arg);
}

static void cmd_script_list(void)
{
	GSList *tmp;
        GString *data;

	if (perl_scripts == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
                            TXT_NO_SCRIPTS_LOADED);
                return;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_SCRIPT_LIST_HEADER);

	data = g_string_new(NULL);
	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		PERL_SCRIPT_REC *rec = tmp->data;

                if (rec->path != NULL)
			g_string_assign(data, rec->path);
		else {
			g_string_assign(data, rec->data);
			if (data->len > 50) {
				g_string_truncate(data, 50);
                                g_string_append(data, " ...");
			}
		}

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_SCRIPT_LIST_LINE, rec->name, data->str);
	}
        g_string_free(data, TRUE);

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_SCRIPT_LIST_FOOTER);
}

static void cmd_load(const char *data, SERVER_REC *server, void *item)
{
        char *rootmodule, *submodule;
	void *free_arg;
	size_t len;

	if (!cmd_get_params(data, &free_arg, 2 , &rootmodule, &submodule))
		return;

	len = strlen(rootmodule);
	if (len > 3 && g_strcmp0(rootmodule + len - 3, ".pl") == 0) {
		/* make /LOAD script.pl work as expected */
		signal_stop();
		cmd_script_load(data);
	}

	cmd_params_free(free_arg);
}

static void sig_script_error(PERL_SCRIPT_REC *script, const char *error)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
		    TXT_SCRIPT_ERROR, script == NULL ? "??" : script->name);

	printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%[-s]%s", error);
}

static void sig_complete_load(GList **list, WINDOW_REC *window,
			      const char *word, const char *line,
			      int *want_space)
{
        char *user_dir;

	if (*line != '\0')
		return;

	/* completing filename parameter for /SCRIPT LOAD */
	user_dir = g_strdup_printf("%s/scripts", get_irssi_dir());
	*list = filename_complete(word, user_dir);
	*list = g_list_concat(*list, filename_complete(word, SCRIPTDIR));
        g_free(user_dir);

	if (*list != NULL) {
		*want_space = FALSE;
		signal_stop();
	}
}

static GList *script_complete(const char *name)
{
	GSList *tmp;
        GList *list;
        int len;

        list = NULL;
        len = strlen(name);
	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		PERL_SCRIPT_REC *rec = tmp->data;

		if (strncmp(rec->name, name, len) == 0)
                        list = g_list_append(list, g_strdup(rec->name));
	}

        return list;
}

static void sig_complete_unload(GList **list, WINDOW_REC *window,
				const char *word, const char *line,
				int *want_space)
{
	if (*line != '\0')
		return;

	/* completing script parameter for /SCRIPT UNLOAD */
	*list = script_complete(word);
	if (*list != NULL)
		signal_stop();
}

void fe_perl_init(void)
{
	theme_register(feperl_formats);

	command_bind("script", NULL, (SIGNAL_FUNC) cmd_script);
	command_bind("script exec", NULL, (SIGNAL_FUNC) cmd_script_exec);
	command_bind("script load", NULL, (SIGNAL_FUNC) cmd_script_load);
	command_bind("script unload", NULL, (SIGNAL_FUNC) cmd_script_unload);
	command_bind("script reset", NULL, (SIGNAL_FUNC) cmd_script_reset);
	command_bind("script list", NULL, (SIGNAL_FUNC) cmd_script_list);
	command_bind("load", NULL, (SIGNAL_FUNC) cmd_load);
	command_set_options("script exec", "permanent");
	command_set_options("script reset", "autorun");

        signal_add("script error", (SIGNAL_FUNC) sig_script_error);
	signal_add("complete command script load", (SIGNAL_FUNC) sig_complete_load);
	signal_add("complete command script unload", (SIGNAL_FUNC) sig_complete_unload);

        perl_core_print_script_error(FALSE);
	module_register("perl", "fe");
}

void fe_perl_deinit(void)
{
	theme_unregister();

	command_unbind("script", (SIGNAL_FUNC) cmd_script);
	command_unbind("script exec", (SIGNAL_FUNC) cmd_script_exec);
	command_unbind("script load", (SIGNAL_FUNC) cmd_script_load);
	command_unbind("script unload", (SIGNAL_FUNC) cmd_script_unload);
	command_unbind("script reset", (SIGNAL_FUNC) cmd_script_reset);
	command_unbind("script list", (SIGNAL_FUNC) cmd_script_list);
	command_unbind("load", (SIGNAL_FUNC) cmd_load);

        signal_remove("script error", (SIGNAL_FUNC) sig_script_error);
	signal_remove("complete command script load", (SIGNAL_FUNC) sig_complete_load);
	signal_remove("complete command script unload", (SIGNAL_FUNC) sig_complete_unload);

        perl_core_print_script_error(TRUE);
}

void fe_perl_abicheck(int *version)
{
	*version = IRSSI_ABI_VERSION;
}
