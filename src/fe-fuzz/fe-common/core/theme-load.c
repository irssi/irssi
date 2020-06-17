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

#include <irssi/src/fe-text/module.h>
#include <irssi/src/core/modules-load.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/fe-text/module-formats.h> // need to explicitly grab from fe-text
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/core/core.h>
#include <irssi/src/fe-common/core/fe-common-core.h>
#include <irssi/src/core/args.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/irc/core/irc.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-fuzz/null-logger.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	char *irssi_argv[] = { *argv[0], "--home", FHS_PREFIX "/tmp/irssi", NULL };
	int irssi_argc = sizeof(irssi_argv) / sizeof(char *) - 1;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	g_log_set_null_logger();
#endif
	core_register_options();
	fe_common_core_register_options();
	args_execute(irssi_argc, irssi_argv);
	core_preinit((*argv)[0]);
	core_init();
	fe_common_core_init();
	theme_register(gui_text_formats);
	module_register("core", "fe-fuzz");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	THEME_REC *theme;
	gchar *copy = g_strndup((const gchar *)data, size);

	FILE *fp = fopen(FHS_PREFIX "/tmp/irssi/fuzz.theme", "wb");
	if (fp) {
		fwrite(copy, strlen(copy), 1, fp);
		fclose(fp);
	}

	theme = theme_load("fuzz");
	theme_destroy(theme);

	g_free(copy);
	return 0;
}
