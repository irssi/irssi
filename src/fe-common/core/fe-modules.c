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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "modules.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "chat-protocols.h"

#include "printtext.h"

static void sig_module_error(void *number, const char *module,
			     const char *data)
{
	switch (GPOINTER_TO_INT(number)) {
	case MODULE_ERROR_ALREADY_LOADED:
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_MODULE_ALREADY_LOADED, module);
		break;
	case MODULE_ERROR_LOAD:
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_MODULE_LOAD_ERROR, module, data);
		break;
	case MODULE_ERROR_INVALID:
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
			    TXT_MODULE_INVALID, module);
		break;
	}
}

static void sig_module_loaded(MODULE_REC *rec)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_MODULE_LOADED, rec->name);
}

static void sig_module_unloaded(MODULE_REC *rec)
{
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		    TXT_MODULE_UNLOADED, rec->name);
}

static void cmd_load_list(void)
{
	GSList *tmp;

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_MODULE_HEADER);
	for (tmp = modules; tmp != NULL; tmp = tmp->next) {
		MODULE_REC *rec = tmp->data;

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_MODULE_LINE, rec->name);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_MODULE_FOOTER);
}

static char **module_prefixes_get(void)
{
        GSList *tmp;
        char **list, *name;
        int count;

	list = g_new(char *, 2 + 2*g_slist_length(chat_protocols));
	list[0] = "fe";

	count = 1;
	for (tmp = chat_protocols; tmp != NULL; tmp = tmp->next) {
		CHAT_PROTOCOL_REC *rec = tmp->data;

		name = g_strdup(rec->name);
                g_strdown(name);

		list[count++] = name;
                list[count++] = g_strconcat("fe_", name, NULL);
	}
	list[count] = NULL;

        return list;
}

static void module_prefixes_free(char **list)
{
	char **pos = list+1;

	while (*pos != NULL) {
                g_free(*pos);
                pos++;
	}
        g_free(list);
}

/* SYNTAX: LOAD <module> */
static void cmd_load(const char *data)
{
#ifdef HAVE_GMODULE
	char **module_prefixes;

	g_return_if_fail(data != NULL);
	if (*data == '\0')
		cmd_load_list();
	else {
		module_prefixes = module_prefixes_get();
		module_load(data, module_prefixes);
                module_prefixes_free(module_prefixes);
	}
#else
	printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
		  "Dynamic modules loading not supported");
#endif
}

/* SYNTAX: UNLOAD <module> */
static void cmd_unload(const char *data)
{
	MODULE_REC *rec;

	g_return_if_fail(data != NULL);
	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = module_find(data);
	if (rec != NULL) module_unload(rec);
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
