/*
 capsicum.c : Capsicum sandboxing support

    Copyright (C) 2017 Edward Tomasz Napierala <trasz@FreeBSD.org>

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
#include "commands.h"

#include <sys/capsicum.h>
#include <string.h>

static void cmd_capsicum(const char *data, SERVER_REC *server, void *item)
{
	command_runsub("capsicum", data, server, item);
}

static void cmd_capsicum_enter(void)
{
	int error;

	error = cap_enter();
	if (error != 0) {
		signal_emit("capability mode failed", 1, strerror(errno));
	} else {
		signal_emit("capability mode enabled", 0);
	}
}

static void cmd_capsicum_status(void)
{
	u_int mode;
	int error;

	error = cap_getmode(&mode);
	if (error != 0) {
		signal_emit("capability mode failed", 1, strerror(errno));
	} else if (mode == 0) {
		signal_emit("capability mode disabled", 0);
	} else {
		signal_emit("capability mode enabled", 0);
	}
}

void capsicum_init(void)
{

	command_bind("capsicum", NULL, (SIGNAL_FUNC) cmd_capsicum);
	command_bind("capsicum enter", NULL, (SIGNAL_FUNC) cmd_capsicum_enter);
	command_bind("capsicum status", NULL, (SIGNAL_FUNC) cmd_capsicum_status);
}

void capsicum_deinit(void)
{
	command_unbind("capsicum", (SIGNAL_FUNC) cmd_capsicum);
	command_unbind("capsicum enter", (SIGNAL_FUNC) cmd_capsicum_enter);
	command_unbind("capsicum status", (SIGNAL_FUNC) cmd_capsicum_status);
}
