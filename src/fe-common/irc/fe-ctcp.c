/*
 fe-ctcp.c : irssi

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
#include "module-formats.h"
#include "misc.h"
#include "settings.h"

#include "irc.h"
#include "levels.h"
#include "servers.h"
#include "channels.h"
#include "queries.h"
#include "ignore.h"

#include "windows.h"
#include "window-items.h"

static void ctcp_print(const char *pre, const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	char *str;

	g_return_if_fail(data != NULL);

	str = g_strconcat(pre, " ", data, NULL);
	printformat(server, ischannel(*target) ? target : nick, MSGLEVEL_CTCPS,
		    IRCTXT_CTCP_REQUESTED, nick, addr, str, target);
	g_free(str);
}

static void ctcp_default_msg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	ctcp_print("unknown CTCP", data, server, nick, addr, target);
}

static void ctcp_ping_msg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	ctcp_print("CTCP PING", data, server, nick, addr, target);
}

static void ctcp_version_msg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	ctcp_print("CTCP VERSION", data, server, nick, addr, target);
}

static void ctcp_time_msg(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	ctcp_print("CTCP TIME", data, server, nick, addr, target);
}

static void ctcp_default_reply(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	const char *ctcpdata;
	char *ctcp, *ptr;

	g_return_if_fail(data != NULL);

	ctcp = g_strdup(data);
	ptr = strchr(ctcp, ' ');
	if (ptr == NULL)
		ctcpdata = "";
	else {
		*ptr = '\0';
		ctcpdata = ptr+1;
	}

	printformat(server, ischannel(*target) ? target : nick, MSGLEVEL_CTCPS,
		    ischannel(*target) ? IRCTXT_CTCP_REPLY_CHANNEL : IRCTXT_CTCP_REPLY, ctcp, nick, ctcpdata, target);
	g_free(ctcp);
}

static void ctcp_ping_reply(const char *data, IRC_SERVER_REC *server, const char *nick, const char *addr, const char *target)
{
	GTimeVal tv, tv2;
	long usecs;

	g_return_if_fail(data != NULL);

	if (sscanf(data, "%ld %ld", &tv2.tv_sec, &tv2.tv_usec) != 2)
		return;

        g_get_current_time(&tv);
	usecs = get_timeval_diff(&tv, &tv2);
        printformat(server, ischannel(*target) ? target : nick, MSGLEVEL_CTCPS,
                    IRCTXT_CTCP_PING_REPLY, nick, usecs/1000, usecs%1000);
}

void fe_ctcp_init(void)
{
	signal_add("default ctcp msg", (SIGNAL_FUNC) ctcp_default_msg);
	signal_add("ctcp msg ping", (SIGNAL_FUNC) ctcp_ping_msg);
	signal_add("ctcp msg version", (SIGNAL_FUNC) ctcp_version_msg);
	signal_add("ctcp msg time", (SIGNAL_FUNC) ctcp_time_msg);
	signal_add("default ctcp reply", (SIGNAL_FUNC) ctcp_default_reply);
	signal_add("ctcp reply ping", (SIGNAL_FUNC) ctcp_ping_reply);
}

void fe_ctcp_deinit(void)
{
	signal_remove("default ctcp msg", (SIGNAL_FUNC) ctcp_default_msg);
	signal_remove("ctcp msg ping", (SIGNAL_FUNC) ctcp_ping_msg);
	signal_remove("ctcp msg version", (SIGNAL_FUNC) ctcp_version_msg);
	signal_remove("ctcp msg time", (SIGNAL_FUNC) ctcp_time_msg);
	signal_remove("default ctcp reply", (SIGNAL_FUNC) ctcp_default_reply);
	signal_remove("ctcp reply ping", (SIGNAL_FUNC) ctcp_ping_reply);
}
