/*
 theme-load.c : irssi

    Copyright (C) 2018 Joseph Bisch

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
#include "modules-load.h"
#include "levels.h"
#include "../fe-text/module-formats.h" // need to explicitly grab from fe-text
#include "themes.h"
#include "core.h"
#include "fe-common-core.h"
#include "args.h"
#include "printtext.h"
#include "irc.h"
#include "themes.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	core_register_options();
	fe_common_core_register_options();
	char *irssi_argv[] = {*argv[0], "--home", "/tmp/irssi", NULL};
	int irssi_argc = sizeof(irssi_argv) / sizeof(char *) - 1;
	args_execute(irssi_argc, irssi_argv);
	core_preinit((*argv)[0]);
	core_init();
	fe_common_core_init();
	theme_register(gui_text_formats);
	module_register("core", "fe-fuzz");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	gchar *copy = g_strndup((const gchar *)data, size);

	FILE *fp = fopen("/tmp/irssi/fuzz.theme", "wb");
	if (fp) {
		fwrite(copy, strlen(copy), 1, fp);
		fclose(fp);
	}

	THEME_REC *theme = theme_load("fuzz");
	theme_destroy(theme);

	g_free(copy);
	return 0;
}
