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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "printtext.h"

FORMAT_REC fecommon_core_formats[] =
{
    { MODULE_NAME, N_("Core"), 0 },

    /* ---- */
    { NULL, N_("Windows"), 0 },

    { "line_start", N_("%B-%W!%B-%n "), 0 },
    { "line_start_irssi", N_("%B-%W!%B- %WIrssi:%n "), 0 },
    { "timestamp", N_("[$[-2.0]3:$[-2.0]4] "), 6, { 1, 1, 1, 1, 1, 1 } },
    { "daychange", N_("Day changed to $[-2.0]1-$[-2.0]0 $2"), 3, { 1, 1, 1 } },
    { "talking_with", N_("You are now talking with %_$0%_"), 1, { 0 } },

    /* ---- */
    { NULL, N_("Server"), 0 },

    { "looking_up", N_("Looking up %_$0%_"), 1, { 0 } },
    { "connecting", N_("Connecting to %_$0%_ %K[%n$1%K]%n port %_$2%_"), 3, { 0, 0, 1 } },
    { "connection_established", N_("Connection to %_$0%_ established"), 1, { 0 } },
    { "cant_connect", N_("Unable to connect server %_$0%_ port %_$1%_ %K[%n$2%K]"), 3, { 0, 1, 0 } },
    { "connection_lost", N_("Connection lost to %_$0%_"), 1, { 0 } },
    { "server_changed", N_("Changed to %_$2%_ server %_$1%_"), 3, { 0, 0, 0 } },
    { "unknown_server_tag", N_("Unknown server tag %_$0%_"), 1, { 0 } },

    /* ---- */
    { NULL, N_("Highlighting"), 0 },

    { "hilight_header", N_("Highlights:"), 0 },
    { "hilight_line", N_("$[-4]0 $1 $2 $3$3$4$5"), 7, { 1, 0, 0, 0, 0, 0, 0 } },
    { "hilight_footer", "", 0 },
    { "hilight_not_found", N_("Highlight not found: $0"), 1, { 0 } },
    { "hilight_removed", N_("Highlight removed: $0"), 1, { 0 } },

    /* ---- */
    { NULL, N_("Aliases"), 0 },

    { "alias_added", N_("Alias $0 added"), 1, { 0 } },
    { "alias_removed", N_("Alias $0 removed"), 1, { 0 } },
    { "alias_not_found", N_("No such alias: $0"), 1, { 0 } },
    { "aliaslist_header", N_("Aliases:"), 0 },
    { "aliaslist_line", N_("$[10]0 $1"), 2, { 0, 0 } },
    { "aliaslist_footer", "", 0 },

    /* ---- */
    { NULL, N_("Logging"), 0 },

    { "log_opened", N_("Log file %W$0%n opened"), 1, { 0 } },
    { "log_closed", N_("Log file %W$0%n closed"), 1, { 0 } },
    { "log_create_failed", N_("Couldn't create log file %W$0"), 1, { 0 } },
    { "log_locked", N_("Log file %W$0%n is locked, probably by another running Irssi"), 1, { 0 } },
    { "log_not_open", N_("Log file %W$0%n not open"), 1, { 0 } },
    { "log_started", N_("Started logging to file %W$0"), 1, { 0 } },
    { "log_stopped", N_("Stopped logging to file %W$0"), 1, { 0 } },
    { "log_list_header", N_("Logs:"), 0 },
    { "log_list", N_("$0: $1 $2$3$4"), 5, { 0, 0, 0, 0, 0 } },
    { "log_list_footer", N_(""), 0 },
    { "windowlog_file", N_("Window LOGFILE set to $0"), 1, { 0 } },
    { "windowlog_file_logging", N_("Can't change window's logfile while log is on"), 0 },

    /* ---- */
    { NULL, N_("Misc"), 0 },

    { "not_toggle", N_("Value must be either ON, OFF or TOGGLE"), 0 },
    { "perl_error", N_("Perl error: $0"), 1, { 0 } }
};
