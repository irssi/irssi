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

/* clang-format off */
FORMAT_REC fecommon_irc_formats[] = {
	{ MODULE_NAME, "IRC", 0 },

	/* ---- */
	{ NULL, "Server", 0 },

	{ "netsplit", "{netsplit Netsplit} {server $0} <-> {server $1} quits: $2", 3, { 0, 0, 0 } },
	{ "netsplit_more", "{netsplit Netsplit} {server $0} <-> {server $1} quits: $2 (+$3 more, use /NETSPLIT to show all of them)", 4, { 0, 0, 0, 1 } },
	{ "netsplit_join", "{netjoin Netsplit} over, joins: $0", 1, { 0 } },
	{ "netsplit_join_more", "{netjoin Netsplit} over, joins: $0 (+$1 more)", 2, { 0, 1 } },
	{ "no_netsplits", "There are no net splits", 0 },
	{ "netsplits_header", "%#Nick      Channel    Server               Split server", 0 },
	{ "netsplits_line", "%#$[9]0 $[10]1 $[20]2 $3", 4, { 0, 0, 0, 0 } },
	{ "netsplits_footer", "", 0 },
	{ "network_added", "Network $0 saved", 1, { 0 } },
	{ "network_removed", "Network $0 removed", 1, { 0 } },
	{ "network_not_found", "Network $0 not found", 1, { 0 } },
	{ "network_header", "%#Networks:", 0 },
	{ "network_line", "%#$0: $1", 2, { 0, 0 } },
	{ "network_footer", "", 0 },
	{ "setupserver_header", "%#Server               Port  Network    Settings", 0 },
	{ "setupserver_line", "%#%|$[!20]0 $[5]1 $[10]2 $3", 4, { 0, 1, 0, 0 } },
	{ "setupserver_footer", "", 0 },
	{ "server_waiting_cap_ls", "Waiting for CAP LS response...", 2, { 0, 0 } },
	{ "sasl_success", "SASL authentication succeeded", 0 },
	{ "sasl_error", "Cannot authenticate via SASL ($0)", 1, { 0 } },
	{ "cap_req",  "Capabilities requested: $0", 1, { 0 } },
	{ "cap_ls",   "Capabilities supported: $0", 1, { 0 } },
	{ "cap_ack",  "Capabilities acknowledged: $0", 1, { 0 } },
	{ "cap_nak",  "Capabilities refused: $0", 1, { 0 } },
	{ "cap_list", "Capabilities currently enabled: $0", 1, { 0 } },
	{ "cap_new",  "Capabilities now available: $0", 1, { 0 } },
	{ "cap_del",  "Capabilities removed: $0", 1, { 0 } },

	/* ---- */
	{ NULL, "Channels", 0 },

	{ "joinerror_toomany", "Cannot join to channel {channel $0} (You have joined to too many channels)", 1, { 0 } },
	{ "joinerror_full", "Cannot join to channel {channel $0} (Channel is full)", 1, { 0 } },
	{ "joinerror_invite", "Cannot join to channel {channel $0} (You must be invited)", 1, { 0 } },
	{ "joinerror_banned", "Cannot join to channel {channel $0} (You are banned)", 1, { 0 } },
	{ "joinerror_bad_key", "Cannot join to channel {channel $0} (Bad channel key)", 1, { 0 } },
	{ "joinerror_bad_mask", "Cannot join to channel {channel $0} (Bad channel mask)", 1, { 0 } },
	{ "joinerror_secure_only", "Cannot join to channel {channel $0} (Secure clients only)", 1, { 0 } },
	{ "joinerror_unavail", "Cannot join to channel {channel $0} (Channel is temporarily unavailable)", 1, { 0 } },
	{ "joinerror_duplicate", "Channel {channel $0} already exists - cannot create it", 1, { 0 } },
	{ "channel_rejoin", "Channel {channel $0} is temporarily unavailable, this is normally because of netsplits. Irssi will now automatically try to rejoin back to this channel until the join is successful. Use /RMREJOINS command if you wish to abort this.", 1, { 0 } },
	{ "inviting", "Inviting {nick $0} to {channel $1}", 2, { 0, 0 } },
	{ "channel_created", "Channel {channelhilight $0} created $1", 2, { 0, 0 } },
	{ "url", "Home page for {channelhilight $0}: $1", 2, { 0, 0 } },
	{ "topic", "Topic for {channelhilight $0}: $1", 2, { 0, 0 } },
	{ "no_topic", "No topic set for {channelhilight $0}", 1, { 0 } },
	{ "topic_info", "Topic set by {nick $0} {nickhost $2} {comment $1}", 3, { 0, 0, 0 } },
        { "chanmode_change", "mode/{channelhilight $0} {mode $1} by {nick $2}", 4, { 0, 0, 0, 0 } },
        { "server_chanmode_change", "{netsplit ServerMode}/{channelhilight $0} {mode $1} by {nick $2}", 3, { 0, 0, 0 } },
        { "channel_mode", "mode/{channelhilight $0} {mode $1}", 2, { 0, 0 } },
	{ "bantype", "Ban type changed to {channel $0}", 1, { 0 } },
	{ "no_bans", "No bans in channel {channel $0}", 1, { 0 } },
	{ "banlist", "$0 - {channel $1}: ban {ban $2}", 3, { 1, 0, 0 } },
        { "banlist_long", "$0 - {channel $1}: ban {ban $2} {comment by {nick $3}, on $5 ($4 ago)}", 6, { 1, 0, 0, 0, 0, 0 } },
	{ "quietlist", "{channel $0}: quiet {ban $1}", 2, { 0, 0 } },
        { "quietlist_long", "{channel $0}: quiet {ban $1} {comment by {nick $2}, on $4 ($3 ago)}", 5, { 0, 0, 0, 0, 0 } },
	{ "ebanlist", "{channel $0}: ban exception {ban $1}", 2, { 0, 0 } },
        { "ebanlist_long", "{channel $0}: ban exception {ban $1} {comment by {nick $2}, on $4 ($3 ago)}", 5, { 0, 0, 0, 0, 0 } },
	{ "no_invitelist", "Invite list is empty in channel {channel $0}", 1, { 0 } },
	{ "invitelist", "{channel $0}: invite {ban $1}", 2, { 0, 0 } },
	{ "invitelist_long", "{channel $0}: invite {ban $1} {comment by {nick $2}, on $3 ($4 ago)}", 5, { 0, 0, 0, 0, 0 } },
	{ "no_such_channel", "{channel $0}: No such channel", 1, { 0 } },
	{ "channel_synced", "Join to {channel $0} was synced in {hilight $1} secs", 2, { 0, 2 } },
	{ "server_help_start", "$1", 2, { 0, 0 } },
	{ "server_help_txt", "$1", 2, { 0, 0 } },
	{ "server_end_of_help", "$1", 2, { 0, 0 } },

	/* ---- */
	{ NULL, "Nick", 0 },

        { "usermode_change", "Mode change {mode $0} for user {nick $1}", 2, { 0, 0 } },
        { "user_mode", "Your user mode is {mode $0}", 1, { 0 } },
	{ "away", "You have been marked as being away", 0 },
	{ "unaway", "You are no longer marked as being away", 0 },
	{ "nick_away", "{nick $0} is away: $1", 2, { 0, 0 } },
	{ "no_such_nick", "{nick $0}: No such nick/channel", 1, { 0 } },
	{ "nick_in_use", "Nick {nick $0} is already in use", 1, { 0 } },
	{ "nick_unavailable", "Nick {nick $0} is temporarily unavailable", 1, { 0 } },
        { "your_nick_owned", "Your nick is in use by {nick $3} {comment $1@$2}", 4, { 0, 0, 0, 0 } },

	/* ---- */
	{ NULL, "Who queries", 0 },

	{ "whois", "{nick $0} {nickhost $1@$2}%:{whois ircname $3}", 4, { 0, 0, 0, 0 } },
	{ "whowas", "{nick $0} {nickhost $1@$2}%:{whois was $3}", 4, { 0, 0, 0, 0 } },
	{ "whois_idle", "{whois idle %|$1 days $2 hours $3 mins $4 secs}", 5, { 0, 1, 1, 1, 1 } },
	{ "whois_idle_signon", "{whois idle %|$1 days $2 hours $3 mins $4 secs {comment signon: $5}}", 6, { 0, 1, 1, 1, 1, 0 } },
	{ "whois_server", "{whois server %|$1 {comment $2}}", 3, { 0, 0, 0 } },
	{ "whois_oper", "{whois  {hilight $1}}", 2, { 0, 0 } },
	{ "whois_modes", "{whois modes $1}", 2, { 0, 0 } },
	{ "whois_realhost", "{whois hostname $1-}", 3, { 0, 0, 0 } },
	{ "whois_usermode", "{whois usermode $1}", 2, { 0, 0 } },
	{ "whois_channels", "{whois channels %|$1}", 2, { 0, 0 } },
	{ "whois_away", "{whois away %|$1}", 2, { 0, 0 } },
	{ "whois_special", "{whois  %|$1}", 2, { 0, 0 } },
	{ "whois_extra", "{whois account %|$1}", 2, { 0, 0 } },
	{ "end_of_whois", "End of WHOIS", 1, { 0 } },
	{ "end_of_whowas", "End of WHOWAS", 1, { 0 } },
	{ "whois_not_found", "There is no such nick $0", 1, { 0 } },
        { "who", "%#{channelhilight $[-10]0} %|{nick $[!9]1} $[!3]2 $[!2]3 $4@$5 {comment {hilight $6}}", 8, { 0, 0, 0, 0, 0, 0, 0, 0 } },
	{ "end_of_who", "End of /WHO list", 1, { 0 } },

	/* ---- */
	{ NULL, "Your messages", 0 },

	{ "own_notice", "{ownnotice notice $0}$1", 2, { 0, 0 } },
	{ "own_action", "{ownaction $0}$1", 3, { 0, 0, 0 } },
	{ "own_action_target", "{ownaction_target $0 $2}$1", 3, { 0, 0, 0 } },
	{ "own_ctcp", "{ownctcp ctcp $0}$1 $2", 3, { 0, 0, 0 } },

	/* ---- */
	{ NULL, "Received messages", 0 },

	{ "notice_server", "{servernotice $0}$1", 2, { 0, 0 } },
	{ "notice_public", "{pubnotice $3 $0}$2", 4, { 0, 0, 0, 0 } },
	{ "notice_private", "{notice $0}$2", 3, { 0, 0, 0 } },
	{ "action_private", "{pvtaction $0}$2", 3, { 0, 0, 0 } },
	{ "action_private_query", "{pvtaction_query $0}$2", 3, { 0, 0, 0 } },
	{ "action_public", "{pubaction $0}$1", 2, { 0, 0 } },
	{ "action_public_channel", "{pubaction $0{msgchannel $1}}$2", 3, { 0, 0, 0 } },

	/* ---- */
	{ NULL, "CTCPs", 0 },

	{ "ctcp_reply", "CTCP {hilight $0} reply from {nick $1}: $2", 3, { 0, 0, 0 } },
	{ "ctcp_reply_channel", "CTCP {hilight $0} reply from {nick $1} in channel {channel $3}: $2", 4, { 0, 0, 0, 0 } },
	{ "ctcp_ping_reply", "CTCP {hilight PING} reply from {nick $0}: $1.$[-3.0]2 seconds", 3, { 0, 2, 2 } },
	{ "ctcp_requested", "{ctcp {hilight $0} {comment $1} requested CTCP {hilight $2} from {nick $4}}: $3", 5, { 0, 0, 0, 0, 0 } },
	{ "ctcp_requested_unknown", "{ctcp {hilight $0} {comment $1} requested unknown CTCP {hilight $2} from {nick $4}}: $3", 5, { 0, 0, 0, 0, 0 } },

	/* ---- */
	{ NULL, "Other server events", 0 },

	{ "online", "Users online: {hilight $0}", 1, { 0 } },
	{ "pong", "PONG received from $0: $1", 2, { 0, 0 } },
	{ "wallops", "{wallop WALLOP {wallop_nick $0}} $1", 2, { 0, 0 } },
	{ "action_wallops", "{wallop WALLOP {wallop_action $0}} $1", 2, { 0, 0 } },
        { "kill", "You were {error killed} by {nick $0} {nickhost $1} {reason $2} {comment Path: $3}", 4, { 0, 0, 0, 0 } },
        { "kill_server", "You were {error killed} by {server $0} {reason $1} {comment Path: $2}", 3, { 0, 0, 0 } },
	{ "error", "{error ERROR} $0", 1, { 0 } },
	{ "unknown_mode", "Unknown mode character $0", 1, { 0 } },
	{ "default_event", "$1", 3, { 0, 0, 0 } },
	{ "default_event_server", "[$0] $1", 3, { 0, 0, 0 } },

	/* ---- */
	{ NULL, "Misc", 0 },

	{ "silenced", "Silenced {nick $0}", 1, { 0 } },
	{ "unsilenced", "Unsilenced {nick $0}", 1, { 0 } },
	{ "silence_line", "{nick $0}: silence {ban $1}", 2, { 0, 0 } },
	{ "ask_oper_pass", "Operator password:", 0 },
	{ "accept_list", "Accepted users: {hilight $0}", 1, { 0 } },

	{ NULL, NULL, 0 }
};
/* clang-format on */
