/*
 module-formats.c : irssi

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
#include "formats.h"

FORMAT_REC fecommon_irc_notifylist_formats[] =
{
	{ MODULE_NAME, "Notifylist", 0 },

	/* ---- */
	{ NULL, "Notifylist", 0 },

	{ "notify_join", "{nick $0} [$1@$2] [{hilight $3}] has joined to $4", 5, { 0, 0, 0, 0, 0 } },
	{ "notify_part", "{nick $0} has left $4", 5, { 0, 0, 0, 0, 0 } },
	{ "notify_away", "{nick $0} [$5] [$1@$2] [{hilight $3}] is now away: $4", 6, { 0, 0, 0, 0, 0, 0 } },
	{ "notify_unaway", "{nick $0} [$4] [$1@$2] [{hilight $3}] is now unaway", 5, { 0, 0, 0, 0, 0 } },
	{ "notify_online", "On $0: {hilight $1}", 2, { 0, 0 } },
	{ "notify_offline", "Offline: $0", 1, { 0 } },
	{ "notify_list", "$0: $1 $2", 4, { 0, 0, 0, 0 } },
	{ "notify_list_empty", "The notify list is empty", 0 },

	{ NULL, NULL, 0 },
};
