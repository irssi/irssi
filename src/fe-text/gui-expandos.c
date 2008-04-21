/*
 gui-expandos.c : irssi

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

#include "gui-entry.h"
#include "gui-readline.h"

/* idle time */
static char *expando_idletime(SERVER_REC *server, void *item, int *free_ret)
{
	int diff;

        *free_ret = TRUE;
	diff = (int) (time(NULL) - get_idle_time());
	return g_strdup_printf("%d", diff);
}

/* current contents of the input line */
static char *expando_inputline(SERVER_REC *server, void *item, int *free_ret)
{
	*free_ret = TRUE;
	return gui_entry_get_text(active_entry);
}

/* value of cutbuffer */
static char *expando_cutbuffer(SERVER_REC *server, void *item, int *free_ret)
{
	*free_ret = TRUE;
	return gui_entry_get_cutbuffer(active_entry);
}

void gui_expandos_init(void)
{
	expando_create("E", expando_idletime, NULL);
	expando_create("L", expando_inputline, NULL);
	expando_create("U", expando_cutbuffer, NULL);
}

void gui_expandos_deinit(void)
{
	expando_destroy("E", expando_idletime);
	expando_destroy("L", expando_inputline);
	expando_destroy("U", expando_cutbuffer);
}
