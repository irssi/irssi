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

FORMAT_REC fecommon_core_formats[] = {
	{ MODULE_NAME, "Core", 0 },

	/* ---- */
	{ NULL, "Windows", 0 },

	{ "line_start", "%B-%W!%B-%n ", 0 },
	{ "line_start_irssi", "%B-%W!%B- %WIrssi:%n ", 0 },
	{ "timestamp", "[$[-2.0]3:$[-2.0]4] ", 6, { 1, 1, 1, 1, 1, 1 } },
	{ "servertag", "[$0] ", 1, { 0 } },
	{ "daychange", "Day changed to $[-2.0]{0} $3 $2", 4, { 1, 1, 1, 0 } },
	{ "talking_with", "You are now talking with %_$0%_", 1, { 0 } },
	{ "refnum_too_low", "Window number must be greater than 1", 0 },
	{ "windowlist_header", "Ref Name                 Active item     Server          Level", 0 },
	{ "windowlist_line", "$[3]0 %|$[20]1 $[15]2 $[15]3 $4", 5, { 1, 0, 0, 0, 0 } },
	{ "windowlist_footer", "", 0 },

	/* ---- */
	{ NULL, "Server", 0 },

	{ "looking_up", "Looking up %_$0%_", 1, { 0 } },
	{ "connecting", "Connecting to %_$0%_ %K[%n$1%K]%n port %_$2%_", 3, { 0, 0, 1 } },
	{ "connection_established", "Connection to %_$0%_ established", 1, { 0 } },
	{ "cant_connect", "Unable to connect server %_$0%_ port %_$1%_ %K[%n$2%K]", 3, { 0, 1, 0 } },
	{ "connection_lost", "Connection lost to %_$0%_", 1, { 0 } },
	{ "server_quit", "Disconnecting from server $0: %K[%n$1%K]", 2, { 0, 0 } },
	{ "server_changed", "Changed to %_$2%_ server %_$1%_", 3, { 0, 0, 0 } },
	{ "unknown_server_tag", "Unknown server tag %_$0%_", 1, { 0 } },

	/* ---- */
	{ NULL, "Highlighting", 0 },

	{ "hilight_header", "Highlights:", 0 },
	{ "hilight_line", "$[-4]0 $1 $2 $3$4$5", 7, { 1, 0, 0, 0, 0, 0, 0 } },
	{ "hilight_footer", "", 0 },
	{ "hilight_not_found", "Highlight not found: $0", 1, { 0 } },
	{ "hilight_removed", "Highlight removed: $0", 1, { 0 } },

	/* ---- */
	{ NULL, "Aliases", 0 },

	{ "alias_added", "Alias $0 added", 1, { 0 } },
	{ "alias_removed", "Alias $0 removed", 1, { 0 } },
	{ "alias_not_found", "No such alias: $0", 1, { 0 } },
	{ "aliaslist_header", "Aliases:", 0 },
	{ "aliaslist_line", "$[10]0 $1", 2, { 0, 0 } },
	{ "aliaslist_footer", "", 0 },

	/* ---- */
	{ NULL, "Logging", 0 },

	{ "log_opened", "Log file %_$0%_ opened", 1, { 0 } },
	{ "log_closed", "Log file %_$0%_ closed", 1, { 0 } },
	{ "log_create_failed", "Couldn't create log file %_$0%_: $1", 2, { 0, 0 } },
	{ "log_locked", "Log file %_$0%_ is locked, probably by another running Irssi", 1, { 0 } },
	{ "log_not_open", "Log file %_$0%_ not open", 1, { 0 } },
	{ "log_started", "Started logging to file %_$0", 1, { 0 } },
	{ "log_stopped", "Stopped logging to file %_$0", 1, { 0 } },
	{ "log_list_header", "Logs:", 0 },
	{ "log_list", "$0 $1: $2 $3$4$5", 6, { 1, 0, 0, 0, 0, 0 } },
	{ "log_list_footer", "", 0 },
	{ "windowlog_file", "Window LOGFILE set to $0", 1, { 0 } },
	{ "windowlog_file_logging", "Can't change window's logfile while log is on", 0 },
	{ "no_away_msgs", "No new messages in awaylog", 1, { 0 } },
	{ "away_msgs", "$1 new messages in awaylog:", 2, { 0, 1 } },

	/* ---- */
	{ NULL, "Modules", 0 },

	{ "module_already_loaded", "Module %_$0%_ already loaded", 1, { 0 } },
	{ "module_load_error", "Error loading module %_$0%_: $1", 2, { 0, 0 } },
	{ "module_invalid", "%_$0%_ isn't Irssi module", 1, { 0 } },
	{ "module_loaded", "Loaded module %_$0", 1, { 0 } },
	{ "module_unloaded", "Unloaded module %_$0", 1, { 0 } },

	/* ---- */
	{ NULL, "Misc", 0 },

	{ "not_toggle", "Value must be either ON, OFF or TOGGLE", 0 },
	{ "perl_error", "Perl error: $0", 1, { 0 } },
	{ "option_unknown", "Unknown option: $0", 1, { 0 } },
	{ "option_ambiguous", "Ambiguous option: $0", 1, { 0 } },
	{ "option_missing_arg", "Missing required argument for: $0", 1, { 0 } },
	{ "command_unknown", "Unknown command: $0", 1, { 0 } },
	{ "command_ambiguous", "Ambiguous command: $0", 1, { 0 } },
	{ "not_enough_params", "Not enough parameters given", 0 },
	{ "not_connected", "Not connected to IRC server yet", 0 },
	{ "not_joined", "Not joined to any channels yet", 0 },
	{ "chan_not_found", "Not joined to such channel", 0 },
	{ "chan_not_synced", "Channel not fully synchronized yet, try again after a while", 0 },
	{ "not_good_idea", "Doing this is not a good idea. Add -YES if you really mean it", 0 },

	{ NULL, NULL, 0 }
};
