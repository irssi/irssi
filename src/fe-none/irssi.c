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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "args.h"
#include "signals.h"
#include "core.h"
#include "irc-core.h"

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
	static struct poptOption options[] = {
		POPT_AUTOHELP
		{ "load", 'l', POPT_ARG_STRING, &autoload_module, 0, "Module to load (default = bot)", "MODULE" },
		{ NULL, '\0', 0, NULL }
	};

	autoload_module = NULL;
	args_register(options);

	irssi_gui = IRSSI_GUI_NONE;
	core_init();
	irc_init();

	signal_add("reload", (SIGNAL_FUNC) sig_reload);
	signal_add("gui exit", (SIGNAL_FUNC) sig_exit);
	signal_emit("irssi init finished", 0);
}

void noui_deinit(void)
{
	signal_remove("reload", (SIGNAL_FUNC) sig_reload);
	signal_remove("gui exit", (SIGNAL_FUNC) sig_exit);
	irc_deinit();
	core_deinit();
}

int main(int argc, char **argv)
{
#ifdef HAVE_SOCKS
	SOCKSinit(argv[0]);
#endif
	noui_init();
	args_execute(argc, argv);

	if (autoload_module == NULL)
		autoload_module = "bot";

	do {
		reload = FALSE;
		/*FIXME:module_load(autoload_module, "");*/
		main_loop = g_main_new(TRUE);
		g_main_run(main_loop);
		g_main_destroy(main_loop);
	}
	while (reload);
	noui_deinit();

	return 0;
}
