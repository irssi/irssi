/*
 fe-common-core.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "modules.h"
#include "modules-load.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "chat-protocols.h"

#include "printtext.h"

#ifdef HAVE_GMODULE

static void sig_module_error(void *number, const char *data,
			     const char *rootmodule, const char *submodule)
{
	switch (GPOINTER_TO_INT(number)) {
	case MODULE_ERROR_ALREADY_LOADED:
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_MODULE_ALREADY_LOADED, rootmodule, submodule);
		break;
	case MODULE_ERROR_LOAD:
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_MODULE_LOAD_ERROR, rootmodule, submodule, data);
		break;
	case MODULE_ERROR_INVALID:
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_MODULE_INVALID, rootmodule, submodule);
		break;
	}
}

static void sig_module_loaded(MODULE_REC *module, MODULE_FILE_REC *file)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_MODULE_LOADED, module->name, file->name);
}

static void sig_module_unloaded(MODULE_REC *module, MODULE_FILE_REC *file)
{
	if (file != NULL && file->gmodule != NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_MODULE_UNLOADED, module->name, file->name);
	}
}

static int module_list_sub(MODULE_REC *module, int mark_type,
			   GString *submodules)
{
	GSList *tmp;
        int all_dynamic, dynamic;

	g_string_truncate(submodules, 0);

        all_dynamic = -1;
	for (tmp = module->files; tmp != NULL; tmp = tmp->next) {
		MODULE_FILE_REC *file = tmp->data;

		/* if there's dynamic and static modules mixed, we'll need
		   to specify them separately */
		if (!mark_type) {
			dynamic = file->gmodule != NULL;
			if (all_dynamic != -1 && all_dynamic != dynamic) {
				return module_list_sub(module, TRUE,
						       submodules);
			}
			all_dynamic = dynamic;
		}

		if (submodules->len > 0)
			g_string_append_c(submodules, ' ');
		g_string_append(submodules, file->name);
		if (mark_type) {
			g_string_append(submodules, file->gmodule == NULL ?
					" (static)" : " (dynamic)");
		}
	}

        return all_dynamic;
}

static void cmd_load_list(void)
{
	GSList *tmp;
	GString *submodules;
        const char *type;
        int dynamic;

        submodules = g_string_new(NULL);

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_MODULE_HEADER);
	for (tmp = modules; tmp != NULL; tmp = tmp->next) {
		MODULE_REC *rec = tmp->data;

                dynamic = module_list_sub(rec, FALSE, submodules);
		type = dynamic == -1 ? "mixed" :
			dynamic ? "dynamic" : "static";

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_MODULE_LINE, rec->name, type, submodules->str);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_MODULE_FOOTER);

	g_string_free(submodules, TRUE);
}

static char **module_prefixes_get(void)
{
        GSList *tmp;
        char **list, *name;
        int count;

	list = g_new(char *, 3 + 3*g_slist_length(chat_protocols));
	list[0] = "fe";
	list[1] = "fe_common";

	count = 2;
	for (tmp = chat_protocols; tmp != NULL; tmp = tmp->next) {
		CHAT_PROTOCOL_REC *rec = tmp->data;

		name = g_ascii_strdown(rec->name, -1);

		list[count++] = name;
                list[count++] = g_strconcat("fe_", name, NULL);
                list[count++] = g_strconcat("fe_common_", name, NULL);
	}
	list[count] = NULL;

        return list;
}

static void module_prefixes_free(char **list)
{
	char **pos = list+2;

	while (*pos != NULL) {
                g_free(*pos);
                pos++;
	}
        g_free(list);
}

/* SYNTAX: LOAD <module> [<submodule>] */
static void cmd_load(const char *data)
{
        char *rootmodule, *submodule;
	char **module_prefixes;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 , &rootmodule, &submodule))
		return;

	if (*rootmodule == '\0')
		cmd_load_list();
	else {
		module_prefixes = module_prefixes_get();
		if (*submodule == '\0')
			module_load(rootmodule, module_prefixes);
		else {
			module_load_sub(rootmodule, submodule,
					module_prefixes);
		}
                module_prefixes_free(module_prefixes);
	}

	cmd_params_free(free_arg);
}

/* SYNTAX: UNLOAD <module> [<submodule>] */
static void cmd_unload(const char *data)
{
	MODULE_REC *module;
        MODULE_FILE_REC *file;
        char *rootmodule, *submodule;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 , &rootmodule, &submodule))
		return;
	if (*rootmodule == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	module = module_find(rootmodule);
	if (module != NULL) {
		if (*submodule == '\0')
			module_unload(module);
		else {
			file = module_file_find(module, submodule);
                        if (file != NULL)
				module_file_unload(file);
			else
                                module = NULL;
		}
	}

	if (module == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
                            TXT_MODULE_NOT_LOADED, rootmodule, submodule);
	}

	cmd_params_free(free_arg);
}

void fe_modules_init(void)
{
	signal_add("module error", (SIGNAL_FUNC) sig_module_error);
	signal_add("module loaded", (SIGNAL_FUNC) sig_module_loaded);
	signal_add("module unloaded", (SIGNAL_FUNC) sig_module_unloaded);

	command_bind("load", NULL, (SIGNAL_FUNC) cmd_load);
	command_bind("unload", NULL, (SIGNAL_FUNC) cmd_unload);
}

void fe_modules_deinit(void)
{
	signal_remove("module error", (SIGNAL_FUNC) sig_module_error);
	signal_remove("module loaded", (SIGNAL_FUNC) sig_module_loaded);
	signal_remove("module unloaded", (SIGNAL_FUNC) sig_module_unloaded);

	command_unbind("load", (SIGNAL_FUNC) cmd_load);
	command_unbind("unload", (SIGNAL_FUNC) cmd_unload);
}

#else /* !HAVE_GMODULE */

static void cmd_load(const char *data)
{
	printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
		  "Dynamic modules loading not supported");
}

void fe_modules_init(void)
{
	command_bind("load", NULL, (SIGNAL_FUNC) cmd_load);
}

void fe_modules_deinit(void)
{
	command_unbind("load", (SIGNAL_FUNC) cmd_load);
}
#endif
