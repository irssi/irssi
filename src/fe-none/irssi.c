/*
 irssi.c : irssi

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
#include <irssi/src/core/modules.h>
#include <irssi/src/core/modules-load.h>
#include <irssi/src/core/args.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/core.h>

static GMainLoop *main_loop;
static char *autoload_module;
static int reload;
static int quitting;

static void sig_exit(void)
{
	quitting = TRUE;
}

static void sig_reload(void)
{
	reload = TRUE;
}

static void autoload_modules(void)
{
	char **list, **module;
	list = g_strsplit_set(settings_get_str("autoload_modules"), " ,", -1);
	for (module = list; *module != NULL; module++) {
		char *tmp;
		if ((tmp = strchr(*module, ':')) != NULL) {
			*tmp = '\0';
			tmp++;
			module_load_sub(*module, tmp, NULL);
		} else {
			module_load(*module, NULL);
		}
	}
	g_strfreev(list);
}

void noui_init(void)
{
	srand(time(NULL));

	irssi_gui = IRSSI_GUI_NONE;
	core_init();

	module_register("core", "fe-none");

	signal_add("reload", (SIGNAL_FUNC) sig_reload);
	signal_add("gui exit", (SIGNAL_FUNC) sig_exit);

	autoload_modules();

	signal_emit("irssi init finished", 0);
}

void noui_deinit(void)
{
	signal_remove("reload", (SIGNAL_FUNC) sig_reload);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_exit);
	core_deinit();
}

int main(int argc, char **argv)
{
	static GOptionEntry options[] = {
		{ "load", 'l', 0, G_OPTION_ARG_STRING, &autoload_module, "Module to load (default = bot)", "MODULE" },
		{ NULL }
	};

	autoload_module = NULL;
	core_register_options();
	args_register(options);
	args_execute(argc, argv);
	core_preinit(argv[0]);

	noui_init();

	if (autoload_module == NULL)
		autoload_module = "bot";

	do {
		reload = FALSE;
		module_load(autoload_module, NULL);
		main_loop = g_main_loop_new(NULL, TRUE);
		while (!quitting && !reload) {
			if (sigterm_received) {
				sigterm_received = FALSE;
				signal_emit("gui exit", 0);
			}

			g_main_context_iteration(NULL, TRUE);
		}
		g_main_loop_unref(main_loop);
	}
	while (reload);
	noui_deinit();

	return 0;
}
