/*
 fe-expandos.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "expandos.h"
#include "fe-windows.h"

/* Window ref# */
static char *expando_winref(SERVER_REC *server, void *item, int *free_ret)
{
	if (active_win == NULL)
		return "";

        *free_ret = TRUE;
	return g_strdup_printf("%d", active_win->refnum);
}

/* Window name */
static char *expando_winname(SERVER_REC *server, void *item, int *free_ret)
{
	if (active_win == NULL)
		return "";

	return active_win->name;
}

void fe_expandos_init(void)
{
	expando_create("winref", expando_winref,
		       "window changed", EXPANDO_ARG_NONE,
		       "window refnum changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("winname", expando_winname,
		       "window changed", EXPANDO_ARG_NONE,
		       "window name changed", EXPANDO_ARG_WINDOW, NULL);
}

void fe_expandos_deinit(void)
{
	expando_destroy("winref", expando_winref);
	expando_destroy("winname", expando_winname);
}
