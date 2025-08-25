/*
 event-get-params.c : irssi

    Copyright (C) 2017 Joseph Bisch

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
#include <irssi/src/fe-fuzz/null-logger.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	g_log_set_null_logger();
#endif
	core_register_options();
	fe_common_core_register_options();
	/* no args */
	args_execute(0, NULL);
	core_preinit((*argv)[0]);
	core_init();
	fe_common_core_init();
	theme_register(gui_text_formats);
	module_register("core", "fe-fuzz");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	uint8_t count = *data;
	gchar *copy;

	char *output0;
	char *output1;
	char *output2;
	char *output3;
	char *params;

	if (size < 1) {
		return 0;
	}

	copy = g_strndup((const gchar *)data+1, size-1);

	if (count % 8 == 0) {
		params = event_get_params(copy, 1 | PARAM_FLAG_GETREST, &output0);
	} else if (count % 8 == 1) {
		params = event_get_params(copy, 2 | PARAM_FLAG_GETREST, &output0, &output1);
	} else if (count % 8 == 2) {
		params = event_get_params(copy, 3 | PARAM_FLAG_GETREST, &output0, &output1, &output2);
	} else if (count % 8 == 3) {
		params = event_get_params(copy, 4 | PARAM_FLAG_GETREST, &output0, &output1, &output2, &output3);
	} else if (count % 8 == 4) {
		params = event_get_params(copy, 1, &output0);
	} else if (count % 8 == 5) {
		params = event_get_params(copy, 2, &output0, &output1);
	} else if (count % 8 == 6) {
		params = event_get_params(copy, 3, &output0, &output1, &output2);
	} else {
		params = event_get_params(copy, 4, &output0, &output1, &output2, &output3);
	}
	g_free(params);
	g_free(copy);
	return 0;
}
