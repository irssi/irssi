/*
 fe-common-irc.c : irssi

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
#include <irssi/src/core/modules.h>
#include <irssi/src/fe-common/irc/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-common/irc/fe-irc-server.h>
#include <irssi/src/fe-common/irc/fe-irc-channels.h>

void fe_irc_queries_init(void);
void fe_irc_queries_deinit(void);

void fe_irc_layout_init(void);
void fe_irc_layout_deinit(void);

void fe_irc_messages_init(void);
void fe_irc_messages_deinit(void);

void fe_irc_commands_init(void);
void fe_irc_commands_deinit(void);

void fe_ircnet_init(void);
void fe_ircnet_deinit(void);

void fe_ctcp_init(void);
void fe_ctcp_deinit(void);

void fe_events_init(void);
void fe_events_deinit(void);

void fe_events_numeric_init(void);
void fe_events_numeric_deinit(void);

void fe_modes_init(void);
void fe_modes_deinit(void);

void fe_netsplit_init(void);
void fe_netsplit_deinit(void);

void fe_netjoin_init(void);
void fe_netjoin_deinit(void);

void fe_whois_init(void);
void fe_whois_deinit(void);

void fe_sasl_init(void);
void fe_sasl_deinit(void);

void fe_cap_init(void);
void fe_cap_deinit(void);

void irc_completion_init(void);
void irc_completion_deinit(void);

void fe_common_irc_init(void)
{
	settings_add_bool("lookandfeel", "show_away_once", TRUE);

	theme_register(fecommon_irc_formats);

	fe_irc_channels_init();
	fe_irc_queries_init();
	fe_irc_messages_init();
	fe_irc_commands_init();
	fe_ircnet_init();
	fe_irc_server_init();
	fe_ctcp_init();
	fe_events_init();
	fe_events_numeric_init();
	fe_modes_init();
	fe_netsplit_init();
	fe_netjoin_init();
        fe_whois_init();
	fe_sasl_init();
	fe_cap_init();
        irc_completion_init();

	settings_check();
	module_register("irc", "fe-common");
}

void fe_common_irc_deinit(void)
{
	fe_irc_channels_deinit();
	fe_irc_queries_deinit();
	fe_irc_messages_deinit();
	fe_irc_commands_deinit();
	fe_ircnet_deinit();
	fe_irc_server_deinit();
	fe_ctcp_deinit();
	fe_events_deinit();
	fe_events_numeric_deinit();
	fe_modes_deinit();
	fe_netsplit_deinit();
	fe_netjoin_deinit();
        fe_whois_deinit();
	fe_sasl_deinit();
	fe_cap_deinit();
        irc_completion_deinit();

	theme_unregister();
}

MODULE_ABICHECK(fe_common_irc)
