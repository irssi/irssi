/*
 autorun.c : irssi

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
#include "signals.h"
#include "line-split.h"
#include "special-vars.h"

#include "fe-windows.h"

static void sig_autorun(void)
{
	char tmpbuf[1024], *str, *path;
	LINEBUF_REC *buffer = NULL;
	int f, ret, recvlen;

	/* open ~/.irssi/startup and run all commands in it */
	path = g_strdup_printf("%s/.irssi/startup", g_get_home_dir());
	f = open(path, O_RDONLY);
	g_free(path);
	if (f == -1) {
		/* file not found */
		return;
	}

	do {
		recvlen = read(f, tmpbuf, sizeof(tmpbuf));

		ret = line_split(tmpbuf, recvlen, &str, &buffer);
		if (ret > 0) eval_special_string(str, "", active_win->active_server, active_win->active);
	} while (ret > 0);
	line_split_free(buffer);

	close(f);
}

void autorun_init(void)
{
	signal_add_last("irssi init finished", (SIGNAL_FUNC) sig_autorun);
}

void autorun_deinit(void)
{
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_autorun);
}
