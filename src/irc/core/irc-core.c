/*
 irc-core.c : irssi

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

#include "irc-server.h"
#include "channels.h"
#include "query.h"

#include "ctcp.h"
#include "ignore.h"
#include "irc.h"
#include "netsplit.h"

void irc_commands_init(void);
void irc_commands_deinit(void);

void irc_rawlog_init(void);
void irc_rawlog_deinit(void);

void irc_special_vars_init(void);
void irc_special_vars_deinit(void);

void irc_log_init(void);
void irc_log_deinit(void);

void lag_init(void);
void lag_deinit(void);

void irc_core_init(void)
{
	irc_servers_init();
	channels_init();
	query_init();

	ctcp_init();
	irc_commands_init();
	irc_irc_init();
	lag_init();
	netsplit_init();
	ignore_init();
	irc_rawlog_init();
	irc_special_vars_init();
	irc_log_init();
}

void irc_core_deinit(void)
{
        irc_log_deinit();
	irc_special_vars_deinit();
	irc_rawlog_deinit();
	ignore_deinit();
	netsplit_deinit();
	lag_deinit();
	irc_irc_deinit();
	irc_commands_deinit();
	ctcp_deinit();

	query_deinit();
	channels_deinit();
	irc_servers_deinit();
}
