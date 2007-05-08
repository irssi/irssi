/*
 bot.c : IRC bot plugin for irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "modules.h"

void bot_irc_commands_deinit(void);
void bot_irc_commands_init(void);

void bot_events_init(void);
void bot_events_deinit(void);

void bot_users_init(void);
void bot_users_deinit(void);

void botnet_init(void);
void botnet_deinit(void);

void irc_bot_init(void)
{
	bot_users_init();
	bot_irc_commands_init();
	bot_events_init();
	botnet_init();

        module_register("bot", "irc");
}

void irc_bot_deinit(void)
{
	bot_users_deinit();
	bot_irc_commands_deinit();
	bot_events_deinit();
	botnet_deinit();
}
