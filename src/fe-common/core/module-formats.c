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
#include <irssi/src/fe-common/core/formats.h>

FORMAT_REC fecommon_core_formats[] = {
	/* clang-format off */
	{ MODULE_NAME, "Core", 0 },

	/* ---- */
	{ NULL, "Windows", 0 },

	{ "line_start", "{line_start}", 0 },
	{ "line_start_irssi", "{line_start}{hilight Irssi:} ", 0 },
        { "timestamp", "{timestamp $Z} ", 0 },
	{ "servertag", "[$0] ", 1, { 0 } },
	{ "daychange", "Day changed to %%d %%b %%Y", 0 },
	{ "talking_with", "You are now talking with {nick $0}", 1, { 0 } },
	{ "refnum_too_low", "Window number must be greater than 1", 0 },
	{ "error_server_sticky", "Window's server is sticky and it cannot be changed without -unsticky option", 0 },
	{ "set_server_sticky", "Window's server set sticky", 1, { 0 } },
	{ "unset_server_sticky", "Window's server isn't sticky anymore", 0 },
	{ "window_name_not_unique", "Window names must be unique", 1, { 0 } },
	{ "window_level", "Window level is $0", 1, { 0 } },
	{ "window_set_immortal", "Window is immortal", 0 },
	{ "window_unset_immortal", "Window isn't immortal", 0 },
	{ "window_immortal_error", "Window is immortal, if you really want to close it, say /WINDOW IMMORTAL OFF", 0 },
	{ "windowlist_header", "%#Ref  Name                 Active item     Server          Level", 0 },
	{ "windowlist_line", "%#$[4]0 %|$[20]1 $[15]2 $[15]3 $4", 5, { 1, 0, 0, 0, 0 } },
	{ "windowlist_footer", "", 0 },
	{ "windows_layout_saved", "Layout of windows is now remembered", 0 },
	{ "windows_layout_reset", "Layout of windows reset to defaults", 0 },
	{ "window_info_header", "", 0 },
	{ "window_info_footer", "", 0 },
	{ "window_info_refnum", "%#Window  : {hilight #$0}", 1, { 1 } },
	{ "window_info_refnum_sticky", "%#Window  : {hilight #$0 (sticky)}", 1, { 1 } },
	{ "window_info_name", "%#Name    : $0", 1, { 0 } },
	{ "window_info_history", "%#History : $0", 1, { 0 } },
	{ "window_info_immortal", "%#Immortal: yes", 0 },
	{ "window_info_size", "%#Size    : $0x$1", 2, { 1, 1 } },
	{ "window_info_level", "%#Level   : $0", 1, { 0 } },
	{ "window_info_server", "%#Server  : $0", 1, { 0 } },
	{ "window_info_server_sticky", "%#Server  : $0 (sticky)", 1, { 0 } },
	{ "window_info_theme", "%#Theme   : $0$1", 2, { 0, 0 } },
	{ "window_info_bound_items_header", "%#Bounds  : {hilight Name                           Server tag}", 0 },
	{ "window_info_bound_item", "%#        : $[!30]0 $[!15]1 $2", 3, { 0, 0, 0 } },
	{ "window_info_bound_items_footer", "", 0 },
	{ "window_info_items_header", "%#Items   : {hilight Name                           Server tag}", 0 },
	{ "window_info_item", "%# $[7]0: $[!30]1 $2", 3, { 0, 0, 0 } },
	{ "window_info_items_footer", "", 0 },

	/* ---- */
	{ NULL, "Server", 0 },

	{ "looking_up", "Looking up {server $0}", 1, { 0 } },
	{ "connecting", "Connecting to {server $0} [$1] port {hilight $2}", 3, { 0, 0, 1 } },
	{ "reconnecting", "Reconnecting to {server $0} [$1] port {hilight $2} - use /RMRECONNS to abort", 3, { 0, 0, 1 } },
	{ "connection_established", "Connection to {server $0} established", 1, { 0 } },
	{ "cant_connect", "Unable to connect server {server $0} port {hilight $1} {reason $2}", 3, { 0, 1, 0 } },
	{ "connection_lost", "Connection lost to {server $0}", 1, { 0 } },
	{ "lag_disconnected", "No PONG reply from server {server $0} in $1 seconds, disconnecting", 2, { 0, 1 } },
	{ "disconnected", "Disconnected from {server $0} {reason $1}", 2, { 0, 0 } },
	{ "server_quit", "Disconnecting from server {server $0}: {reason $1}", 2, { 0, 0 } },
	{ "server_changed", "Changed to {hilight $2} server {server $1}", 3, { 0, 0, 0 } },
	{ "unknown_server_tag", "Unknown server tag {server $0}", 1, { 0 } },
	{ "no_connected_servers", "Not connected to any servers", 0 },
	{ "server_list", "{server $0}: $1:$2 ($3)", 5, { 0, 0, 1, 0, 0 } },
	{ "server_lookup_list", "{server $0}: $1:$2 ($3) (connecting...)", 5, { 0, 0, 1, 0, 0 } },
	{ "server_reconnect_list", "{server $0}: $1:$2 ($3) ($5 left before reconnecting)", 6, { 0, 0, 1, 0, 0, 0 } },
	{ "server_reconnect_removed", "Removed reconnection to server {server $0} port {hilight $1}", 3, { 0, 1, 0 } },
	{ "server_reconnect_not_found", "Reconnection tag {server $0} not found", 1, { 0 } },
	{ "setupserver_added", "Server {server $0} saved", 2, { 0, 1 } },
	{ "setupserver_removed", "Server {server $0} {hilight $1} removed", 2, { 0, 1 } },
	{ "setupserver_not_found", "Server {server $0} {hilight $1} not found", 2, { 0, 1 } },
	{ "your_nick", "Your nickname is {nick $0}", 1, { 0 } },

	/* ---- */
	{ NULL, "Channels", 0 },

	{ "join", "{channick_hilight $0} {chanhost_hilight $1} has joined {channel $2}", 5, { 0, 0, 0, 0, 0 } },
	{ "join_extended", "{channick_hilight $0} {chanhost_hilight $1} has joined {channel $2} {comment realname {reason $4}}", 5, { 0, 0, 0, 0, 0 } },
	{ "join_extended_account", "{channick_hilight $0} {chanhost_hilight $1} has joined {channel $2} {reason account {hilight $3}} {comment realname {reason $4}}", 5, { 0, 0, 0, 0, 0 } },
	{ "host_changed", "{channick_hilight $0} {chanhost_hilight $1} has changed host", 4, { 0, 0, 0, 0 } },
	{ "logged_out", "{channick $0} {chanhost $1} has logged out of their account", 4, { 0, 0, 0, 0 } },
	{ "logged_in", "{channick_hilight $0} {chanhost_hilight $1} has logged in to account {hilight $2}", 4, { 0, 0, 0, 0 } },
	{ "part", "{channick $0} {chanhost $1} has left {channel $2} {reason $3}", 4, { 0, 0, 0, 0 } },
	{ "kick", "{channick $0} was kicked from {channel $1} by {nick $2} {reason $3}", 5, { 0, 0, 0, 0, 0 } },
	{ "quit", "{channick $0} {chanhost $1} has quit {reason $2}", 4, { 0, 0, 0, 0 } },
	{ "quit_once", "{channel $3} {channick $0} {chanhost $1} has quit {reason $2}", 4, { 0, 0, 0, 0 } },
	{ "invite", "{nick $0} invites you to {channel $1}", 3, { 0, 0, 0 } },
	{ "not_invited", "You have not been invited to a channel!", 0 },
	{ "invite_other", "{nick $0} has been invited to {channel $2} by {channick_hilight $1}", 4, { 0, 0, 0, 0 } },
	{ "new_topic", "{nick $0} changed the topic of {channel $1} to: $2", 4, { 0, 0, 0, 0 } },
	{ "topic_unset", "Topic unset by {nick $0} on {channel $1}", 4, { 0, 0, 0, 0 } },
	{ "your_nick_changed", "You're now known as {nick $1}", 4, { 0, 0, 0, 0 } },
	{ "nick_changed", "{channick $0} is now known as {channick_hilight $1}", 4, { 0, 0, 0, 0 } },
	{ "notify_away_channel", "{channick $0} {chanhost $1} is now away: {reason $2}", 4, { 0, 0, 0, 0 } },
	{ "notify_unaway_channel", "{channick_hilight $0} {chanhost $1} is no longer away", 4, { 0, 0, 0, 0 } },
	{ "talking_in", "You are now talking in {channel $0}", 1, { 0 } },
	{ "not_in_channels", "You are not on any channels", 0 },
	{ "current_channel", "Current channel {channel $0}", 1, { 0 } },
	{ "names", "{names_users Users {names_channel $0}}", 6, { 0, 1, 1, 1, 1, 1 } },
	{ "names_prefix", "%#{names_prefix $0}", 1, { 0 } },
        { "names_nick_op", "{names_nick_op $0 $1}", 2, { 0, 0 } },
        { "names_nick_halfop", "{names_nick_halfop $0 $1}", 2, { 0, 0 } },
        { "names_nick_voice", "{names_nick_voice $0 $1}", 2, { 0, 0 } },
        { "names_nick", "{names_nick $0 $1}", 2, { 0, 0 } },
        { "endofnames", "{channel $0}: Total of {hilight $1} nicks {comment {hilight $2} ops, {hilight $3} halfops, {hilight $4} voices, {hilight $5} normal}", 6, { 0, 1, 1, 1, 1, 1 } },
	{ "chanlist_header", "%#You are on the following channels:", 0 },
	{ "chanlist_line", "%#{channel $[-10]0} %|+$1 ($2): $3", 4, { 0, 0, 0, 0 } },
	{ "chansetup_not_found", "Channel {channel $0} not found", 2, { 0, 0 } },
	{ "chansetup_added", "Channel {channel $0} saved", 2, { 0, 0 } },
	{ "chansetup_removed", "Channel {channel $0} removed", 2, { 0, 0 } },
	{ "chansetup_header", "%#Channel         Network    Password   Settings", 0 },
	{ "chansetup_line", "%#{channel $[15]0} %|$[10]1 $[10]2 $3", 4, { 0, 0, 0, 0 } },
	{ "chansetup_footer", "", 0 },

	/* ---- */
	{ NULL, "Messages", 0 },

	{ "own_msg", "{ownmsgnick $2 {ownnick $0}}$1", 3, { 0, 0, 0 } },
	{ "own_msg_channel", "{ownmsgnick $3 {ownnick $0}{msgchannel $1}}$2", 4, { 0, 0, 0, 0 } },
	{ "own_msg_private", "{ownprivmsg msg $0}$1", 2, { 0, 0 } },
	{ "own_msg_private_query", "{ownprivmsgnick {ownprivnick $2}}$1", 3, { 0, 0, 0 } },
	{ "pubmsg_me", "{pubmsgmenick $2 {menick $0}}$1", 3, { 0, 0, 0 } },
	{ "pubmsg_me_channel", "{pubmsgmenick $3 {menick $0}{msgchannel $1}}$2", 4, { 0, 0, 0, 0 } },
	{ "pubmsg_hilight", "{pubmsghinick $0 $3 $1}$2", 4, { 0, 0, 0, 0 } },
	{ "pubmsg_hilight_channel", "{pubmsghinick $0 $4 $1{msgchannel $2}}$3", 5, { 0, 0, 0, 0, 0 } },
	{ "pubmsg", "{pubmsgnick $2 {pubnick $0}}$1", 3, { 0, 0, 0 } },
	{ "pubmsg_channel", "{pubmsgnick $3 {pubnick $0}{msgchannel $1}}$2", 4, { 0, 0, 0, 0 } },
	{ "msg_private", "{privmsg $0 $1}$2", 3, { 0, 0, 0 } },
	{ "msg_private_query", "{privmsgnick $0}$2", 3, { 0, 0, 0 } },
	{ "no_msgs_got", "You have not received a message from anyone yet", 0 },
	{ "no_msgs_sent", "You have not sent a message to anyone yet", 0 },

	/* ---- */
	{ NULL, "Queries", 0 },

	{ "query_start", "Starting query in {server $1} with {nick $0}", 2, { 0, 0 } },
	{ "query_stop", "Closing query with {nick $0}", 1, { 0 } },
	{ "no_query", "No query with {nick $0}", 1, { 0 } },
	{ "query_server_changed", "Query with {nick $0} changed to server {server $1}", 2, { 0, 0 } },

	/* ---- */
	{ NULL, "Highlighting", 0 },

	{ "hilight_header", "%#Highlights:", 0 },
	{ "hilight_line", "%#$[-4]0 $1 $2 $3$4", 5, { 1, 0, 0, 0, 0 } },
	{ "hilight_footer", "", 0 },
	{ "hilight_not_found", "Highlight not found: $0", 1, { 0 } },
	{ "hilight_removed", "Highlight removed: $0", 1, { 0 } },

	/* ---- */
	{ NULL, "Aliases", 0 },

	{ "alias_added", "Alias $0 added", 1, { 0 } },
	{ "alias_removed", "Alias $0 removed", 1, { 0 } },
	{ "alias_not_found", "No such alias: $0", 1, { 0 } },
	{ "aliaslist_header", "%#Aliases:", 0 },
	{ "aliaslist_line", "%#$[10]0 $1", 2, { 0, 0 } },
	{ "aliaslist_footer", "", 0 },

	/* ---- */
	{ NULL, "Logging", 0 },

	{ "log_opened", "Log file {hilight $0} opened", 1, { 0 } },
	{ "log_closed", "Log file {hilight $0} closed", 1, { 0 } },
	{ "log_create_failed", "Couldn't create log file {hilight $0}: $1", 2, { 0, 0 } },
	{ "log_locked", "Log file {hilight $0} is locked, probably by another running Irssi", 1, { 0 } },
	{ "log_not_open", "Log file {hilight $0} not open", 1, { 0 } },
	{ "log_started", "Started logging to file {hilight $0}", 1, { 0 } },
	{ "log_stopped", "Stopped logging to file {hilight $0}", 1, { 0 } },
	{ "log_list_header", "%#Logs:", 0 },
	{ "log_list", "%#$0 $1: $2 $3$4$5", 6, { 1, 0, 0, 0, 0, 0 } },
	{ "log_list_footer", "", 0 },
	{ "windowlog_file", "Window LOGFILE set to $0", 1, { 0 } },
	{ "windowlog_file_logging", "Can't change window's logfile while log is on", 0 },
	{ "no_away_msgs", "No new messages in awaylog", 1, { 0 } },
	{ "away_msgs", "{hilight $1} new messages in awaylog:", 2, { 0, 1 } },

	/* ---- */
	{ NULL, "Modules", 0 },

	{ "module_header", "%#Module               Type    Submodules", 0, },
	{ "module_line", "%#$[!20]0 $[7]1 $2", 3, { 0, 0, 0 } },
	{ "module_footer", "", 0, },
	{ "module_already_loaded", "Module {hilight $0/$1} already loaded", 2, { 0, 0 } },
	{ "module_not_loaded", "Module {hilight $0/$1} is not loaded", 2, { 0, 0 } },
	{ "module_load_error", "Error loading module {hilight $0/$1}: $2", 3, { 0, 0, 0 } },
	{ "module_version_mismatch", "{hilight $0/$1} is ABI version $2 but Irssi is version $abiversion, cannot load", 3, { 0, 0, 0 } },
	{ "module_invalid", "{hilight $0/$1} isn't Irssi module", 2, { 0, 0 } },
	{ "module_loaded", "Loaded module {hilight $0/$1}", 2, { 0, 0 } },
	{ "module_unloaded", "Unloaded module {hilight $0/$1}", 2, { 0, 0 } },

	/* ---- */
	{ NULL, "Commands", 0 },

	{ "command_unknown", "Unknown command: $0", 1, { 0 } },
	{ "command_ambiguous", "Ambiguous command: $0", 1, { 0 } },
	{ "option_unknown", "Unknown option: $0", 1, { 0 } },
	{ "option_ambiguous", "Ambiguous option: $0", 1, { 0 } },
	{ "option_missing_arg", "Missing required argument for: $0", 1, { 0 } },
	{ "not_enough_params", "Not enough parameters given", 0 },
	{ "not_connected", "Not connected to server", 0 },
	{ "not_joined", "Not joined to any channel", 0 },
	{ "chan_not_found", "Not joined to such channel", 0 },
	{ "chan_not_synced", "Channel not fully synchronized yet, try again after a while", 0 },
	{ "illegal_proto", "Command isn't designed for the chat protocol of the active server", 0 },
	{ "not_good_idea", "Doing this is not a good idea. Add -YES option to command if you really mean it", 0 },
	{ "invalid_number", "Invalid number", 0 },
	{ "invalid_time", "Invalid timestamp", 0 },
	{ "invalid_level", "Invalid message level", 0 },
	{ "invalid_size", "Invalid size", 0 },
	{ "invalid_charset", "Invalid charset: $0", 1, { 0 } },
	{ "invalid_choice", "Invalid choice, must be one of $0", 1, { 0 } },
	{ "eval_max_recurse", "/eval hit maximum recursion limit", 0 },
	{ "program_not_found", "Could not find file or file is not executable", 0 },
	{ "no_server_defined", "No servers defined for this network, see /help server for how to add one", 0 },

	/* ---- */
	{ NULL, "Themes", 0 },

	{ "theme_saved", "Theme saved to $0", 1, { 0 } },
	{ "theme_save_failed", "Error saving theme to $0: $1", 2, { 0, 0 } },
	{ "theme_not_found", "Theme {hilight $0} not found", 1, { 0 } },
	{ "theme_changed", "Now using theme {hilight $0} ($1)", 2, { 0, 0 } },
	{ "window_theme", "Using theme {hilight $0} in this window", 2, { 0, 0 } },
	{ "window_theme_default", "No theme is set for this window", 0 },
	{ "window_theme_changed", "Now using theme {hilight $0} ($1) in this window", 2, { 0, 0 } },
	{ "window_theme_removed", "Removed theme from this window", 0 },
	{ "format_title", "%:[{hilight $0}] - [{hilight $1}]%:", 2, { 0, 0 } },
	{ "format_subtitle", "[{hilight $0}]", 1, { 0 } },
	{ "format_item", "$0 = $1", 2, { 0, 0 } },

	/* ---- */
	{ NULL, "Ignores", 0 },

	{ "ignored", "Ignoring {hilight $1} from {nick $0}", 2, { 0, 0 } },
	{ "ignored_options", "Ignoring {hilight $1} from {nick $0} {comment $2}", 3, { 0, 0, 0 } },
	{ "unignored", "Unignored {nick $0}", 1, { 0 } },
	{ "ignore_not_found", "{nick $0} is not being ignored", 1, { 0 } },
	{ "ignore_no_ignores", "There are no ignores", 0 },
	{ "ignore_header", "%#Ignore List:", 0 },
	{ "ignore_line", "%#$[-4]0 $1: $2 $3 $4", 4, { 1, 0, 0, 0 } },
	{ "ignore_footer", "", 0 },

	/* ---- */
	{ NULL, "Recode", 0 },

	{ "not_channel_or_query", "The current window is not a channel or query window", 0 },
	{ "conversion_added", "Added {hilight $0}/{hilight $1} to conversion database", 2, { FORMAT_STRING, FORMAT_STRING } },
	{ "conversion_removed", "Removed {hilight $0} from conversion database", 1, { FORMAT_STRING } },
	{ "conversion_not_found", "{hilight $0} not found in conversion database", 1, { FORMAT_STRING } },
	{ "conversion_no_translits", "Transliterations not supported in this system", 0 },
	{ "recode_header", "%#Target                         Character set", 0 },
	{ "recode_line", "%#%|$[!30]0 $1", 2, { FORMAT_STRING, FORMAT_STRING } },

	/* ---- */
	{ NULL, "Misc", 0 },

	{ "unknown_chat_protocol", "Unknown chat protocol: $0", 1, { 0 } },
	{ "unknown_chatnet", "Unknown chat network: $0 (create it with /NETWORK ADD)", 1, { 0 } },
	{ "not_toggle", "Value must be either ON, OFF or TOGGLE", 0 },
	{ "perl_error", "Perl error: $0", 1, { 0 } },
	{ "bind_header", "%#Key                  Action", 0 },
	{ "bind_list", "%#$[!20]0 $1 $2", 3, { 0, 0, 0 } },
	{ "bind_command_list", "$[!30]0 $1", 2, { 0, 0 } },
	{ "bind_footer", "", 0 },
	{ "bind_unknown_id", "Unknown bind action: $0", 1, { 0 } },
	{ "config_saved", "Saved configuration to file $0", 1, { 0 } },
	{ "config_reloaded", "Reloaded configuration", 1, { 0 } },
	{ "config_modified", "Configuration file was modified since irssi was last started - do you want to overwrite the possible changes?", 1, { 0 } },
	{ "glib_error", "{error ($0) $1} $2", 3, { 0, 0, 0 } },
	{ "overwrite_config", "Overwrite config (y/N)?", 0 },
	{ "set_title", "[{hilight $0}]", 1, { 0 } },
	{ "set_item", "$[-!32]0 %_$1", 2, { 0, 0 } },
	{ "set_unknown", "Unknown setting $0", 1, { 0 } },
	{ "set_not_boolean", "Setting {hilight $0} isn't boolean, use /SET", 1, { 0 } },
	{ "no_completions", "There are no completions", 0 },
	{ "completion_removed", "Removed completion $0", 1, { 0 } },
	{ "completion_header", "%#Key        Value                                    Auto", 0 },
	{ "completion_line", "%#$[10]0 $[!40]1 $2", 3, { 0, 0, 0 } },
	{ "completion_footer", "", 0 },
	{ "capsicum_enabled", "Capability mode enabled", 0 },
	{ "capsicum_disabled", "Capability mode not enabled", 0 },
	{ "capsicum_failed", "Capability mode failed: $0", 1, { 0 } },

	/* ---- */
	{ NULL, "TLS", 0 },

	{ "tls_ephemeral_key", "EDH Key: {hilight $0} bit {hilight $1}", 2, { 1, 0 } },
	{ "tls_ephemeral_key_unavailable", "EDH Key: {error N/A}", 0 },
	{ "tls_pubkey",       "Public Key: {hilight $0} bit {hilight $1}, valid from {hilight $2} to {hilight $3}", 4, { 1, 0, 0, 0 } },
	{ "tls_cert_header", "Certificate Chain:", 0 },
	{ "tls_cert_subject", "  Subject: {hilight $0}", 1, { 0 } },
	{ "tls_cert_issuer",  "  Issuer:  {hilight $0}", 1, { 0 } },
	{ "tls_pubkey_fingerprint", "Public Key Fingerprint:  {hilight $0} ({hilight $1})", 2, { 0, 0 } },
	{ "tls_cert_fingerprint", "Certificate Fingerprint: {hilight $0} ({hilight $1})", 2, { 0, 0 } },
	{ "tls_protocol_version", "Protocol: {hilight $0} ({hilight $1} bit, {hilight $2})", 3, { 0, 1, 0 } },

	{ NULL, NULL, 0 }
	/* clang-format on */
};
