/*
 proxy.c : irc proxy

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
#include "settings.h"
#include "levels.h"

void irc_proxy_init(void)
{
	settings_add_str("irssiproxy", "irssiproxy_ports", "");
	settings_add_str("irssiproxy", "irssiproxy_password", "");
	settings_add_str("irssiproxy", "irssiproxy_bind", "");

	if (*settings_get_str("irssiproxy_password") == '\0') {
		/* no password - bad idea! */
		signal_emit("gui dialog", 2, "warning",
			    "Warning!! Password not specified, everyone can "
			    "use this proxy! Use /set irssiproxy_password "
			    "<password> to set it");
	}
	if (*settings_get_str("irssiproxy_ports") == '\0') {
		signal_emit("gui dialog", 2, "warning",
			    "No proxy ports specified. Use /SET "
			    "irssiproxy_ports <ircnet>=<port> <ircnet2>=<port2> "
			    "... to set them.");
	}

	proxy_listen_init();
	settings_check();
        module_register("proxy", "irc");
}

void irc_proxy_deinit(void)
{
	proxy_listen_deinit();
}
