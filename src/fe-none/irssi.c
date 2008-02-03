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
#include "modules.h"
#include "modules-load.h"
#include "args.h"
#include "signals.h"
#include "core.h"

#ifdef HAVE_STATIC_PERL
void perl_core_init(void);
void perl_core_deinit(void);
#endif

void irc_init(void);
void irc_deinit(void);

static GMainLoop *main_loop;
static char *autoload_module;
static int reload;

static void sig_exit(void)
{
	g_main_quit(main_loop);
}

static void sig_reload(void)
{
	reload = TRUE;
}

void noui_init(void)
{
	srand(time(NULL));

	irssi_gui = IRSSI_GUI_NONE;
	core_init();
	irc_init();

	module_register("core", "fe-none");

	signal_add("reload", (SIGNAL_FUNC) sig_reload);
	signal_add("gui exit", (SIGNAL_FUNC) sig_exit);

#ifdef HAVE_STATIC_PERL
        perl_core_init();
#endif

	signal_emit("irssi init finished", 0);
}

void noui_deinit(void)
{
#ifdef HAVE_STATIC_PERL
        perl_core_deinit();
#endif

	signal_remove("reload", (SIGNAL_FUNC) sig_reload);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_exit);
	irc_deinit();
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

#ifdef HAVE_SOCKS
	SOCKSinit(argv[0]);
#endif
	noui_init();

	if (autoload_module == NULL)
		autoload_module = "bot";

	do {
		reload = FALSE;
		module_load(autoload_module, NULL);
		main_loop = g_main_new(TRUE);
		g_main_run(main_loop);
		g_main_destroy(main_loop);
	}
	while (reload);
	noui_deinit();

	return 0;
}
