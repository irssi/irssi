/*
 core.c : irssi

    Copyright (C) 1999 Timo Sirainen

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

#include "modules.h"
#include "pidwait.h"

#include "net-disconnect.h"
#include "signals.h"
#include "settings.h"

#include "server.h"
#include "commands.h"
#include "log.h"
#include "rawlog.h"
#include "special-vars.h"

int irssi_gui;

void core_init(void)
{
	modules_init();
	pidwait_init();

	net_disconnect_init();
	signals_init();
	settings_init();
	commands_init();

	servers_init();
	log_init();
	rawlog_init();
	special_vars_init();
}

void core_deinit(void)
{
	special_vars_deinit();
	rawlog_deinit();
	log_deinit();
	servers_deinit();

	commands_deinit();
	settings_deinit();
	signals_deinit();
	net_disconnect_deinit();

	pidwait_deinit();
	modules_deinit();
}
