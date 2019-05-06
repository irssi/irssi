/*
 args.c : small frontend to GOption command line argument parser

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

#include "module.h"
#include <irssi/src/core/args.h>

static GOptionContext *context = NULL;

void args_register(GOptionEntry *options)
{
	if (context == NULL)
		context = g_option_context_new("");

	g_option_context_add_main_entries(context, options, PACKAGE_TARNAME);
}

void args_execute(int argc, char *argv[])
{
	GError* error = NULL;

	if (context == NULL)
		return;

	g_option_context_parse(context, &argc, &argv, &error);
	g_option_context_free(context);
	context = NULL;

	if (error != NULL) {
		printf("%s\n"
		       "Run '%s --help' to see a full list of "
		       "available command line options.\n",
		       error->message, argv[0]);
		exit(1);
	}
}
