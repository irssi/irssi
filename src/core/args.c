/*
 args.c : small frontend to libPopt command line argument parser

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
#include "args.h"

GArray *iopt_tables = NULL;

void args_register(struct poptOption *options)
{
	if (iopt_tables == NULL) {
		iopt_tables = g_array_new(TRUE, TRUE,
					  sizeof(struct poptOption));
	}

	while (options->longName != NULL || options->shortName != '\0' ||
	       options->arg != NULL) {
		g_array_append_val(iopt_tables, *options);
		options = options+1;
	}
}

void args_execute(int argc, char *argv[])
{
	poptContext con;
	int nextopt;

	if (iopt_tables == NULL)
		return;

	con = poptGetContext(PACKAGE_TARNAME, argc, argv,
			     (struct poptOption *) (iopt_tables->data), 0);
	poptReadDefaultConfig(con, TRUE);

	while ((nextopt = poptGetNextOpt(con)) > 0) ;

	if (nextopt != -1) {
		printf("Error on option %s: %s.\n"
		       "Run '%s --help' to see a full list of "
		       "available command line options.\n",
		       poptBadOption(con, 0), poptStrerror(nextopt), argv[0]);
		exit(1);
	}

	g_array_free(iopt_tables, TRUE);
	iopt_tables = NULL;

        poptFreeContext(con);
}
