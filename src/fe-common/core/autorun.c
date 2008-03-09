/*
 autorun.c : irssi

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
#include "signals.h"
#include "special-vars.h"

#include "fe-windows.h"

void autorun_startup(void)
{
	char *path;
	GIOChannel *handle;
	GString *buf;
	gsize tpos;

	/* open ~/.irssi/startup and run all commands in it */
	path = g_strdup_printf("%s/startup", get_irssi_dir());
	handle = g_io_channel_new_file(path, "r", NULL);
	g_free(path);
	if (handle == NULL) {
		/* file not found */
		return;
	}

	buf = g_string_sized_new(512);
	while (g_io_channel_read_line_string(handle, buf, &tpos, NULL) == G_IO_STATUS_NORMAL) {
		buf->str[tpos] = '\0';
		if (buf->str[0] != '#') {
			eval_special_string(buf->str, "",
					    active_win->active_server,
					    active_win->active);
		}
	}
	g_string_free(buf, TRUE);

	g_io_channel_close(handle);
}
