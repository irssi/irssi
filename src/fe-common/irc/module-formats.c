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

FORMAT_REC fecommon_irc_formats[] = {
	{ MODULE_NAME, "IRC", 0 },

	/* ---- */
	{ NULL, "Server", 0 },

	{ "lag_disconnected", "No PONG reply from server %_$0%_ in $1 seconds, disconnecting", 2, { 0, 1 } },
	{ "disconnected", "Disconnected from %_$0%_ %K[%n$1%K]", 2, { 0, 0 } },
	{ "server_list", "%_$0%_: $1:$2 ($3)", 5, { 0, 0, 1, 0, 0 } },
	{ "server_lookup_list", "%_$0%_: $1:$2 ($3) (connecting...)", 5, { 0, 0, 1, 0, 0 } },
	{ "server_reconnect_list", "%_$0%_: $1:$2 ($3) ($5 left before reconnecting)", 6, { 0, 0, 1, 0, 0, 0 } },
	{ "server_reconnect_removed", "Removed reconnection to server %_$0%_ port %_$1%_", 3, { 0, 1, 0 } },
	{ "server_reconnect_not_found", "Reconnection tag %_$0%_ not found", 1, { 0 } },
	{ "query_server_changed", "Query with %_$2%_ changed to server %_$1%_", 3, { 0, 0, 0 } },
	{ "setupserver_added", "Server $0 saved", 2, { 0, 1 } },
	{ "setupserver_removed", "Server $0 removed", 2, { 0, 1 } },
	{ "setupserver_not_found", "Server $0 not found", 2, { 0, 1 } },
	{ "setupserver_header", "Server               Port  IRC Net    Settings", 0 },
	{ "setupserver_line", "%|$[!20]0 $[5]1 $[10]2 $3", 4, { 0, 1, 0, 0 } },
	{ "setupserver_footer", "", 0 },
	{ "netsplit", "%RNetsplit%n %_$0%_ %_$1%_ quits: $2", 3, { 0, 0, 0 } },
	{ "netsplit_more", "%RNetsplit%n %_$0%_ %_$1%_ quits: $2 (+$3 more, use /NETSPLIT to show all of them)", 4, { 0, 0, 0, 1 } },
	{ "netsplit_join", "%CNetsplit%n over, joins: $0", 1, { 0 } },
	{ "netsplit_join_more", "%CNetsplit%n over, joins: $0 (+$1 more)", 2, { 0, 1 } },
	{ "no_netsplits", "There are no net splits", 0 },
	{ "netsplits_header", "Nick      Channel    Server               Splitted server", 0 },
	{ "netsplits_line", "$[9]0 $[10]1 $[20]2 $3", 4, { 0, 0, 0, 0 } },
	{ "netsplits_footer", "", 0 },
	{ "ircnet_added", "Ircnet $0 saved", 1, { 0 } },
	{ "ircnet_removed", "Ircnet $0 removed", 1, { 0 } },
	{ "ircnet_not_found", "Ircnet $0 not found", 1, { 0 } },
	{ "ircnet_header", "Ircnets:", 0 },
	{ "ircnet_line", "$0: $1", 2, { 0, 0 } },
	{ "ircnet_footer", "", 0 },

	/* ---- */
	{ NULL, "Channels", 0 },

	{ "join", "%c%_$0%_ %K[%c$1%K]%n has joined %_$2", 3, { 0, 0, 0 } },
	{ "part", "%c$0 %K[%n$1%K]%n has left %_$2%_ %K[%n$3%K]", 4, { 0, 0, 0, 0 } },
	{ "joinerror_toomany", "Cannot join to channel %_$0%_ %K(%nYou have joined to too many channels%K)", 1, { 0 } },
	{ "joinerror_full", "Cannot join to channel %_$0%_ %K(%nChannel is full%K)", 1, { 0 } },
	{ "joinerror_invite", "Cannot join to channel %_$0%_ %K(%nYou must be invited%K)", 1, { 0 } },
	{ "joinerror_banned", "Cannot join to channel %_$0%_ %K(%nYou are banned%K)", 1, { 0 } },
	{ "joinerror_bad_key", "Cannot join to channel %_$0%_ %K(%nBad channel key%K)", 1, { 0 } },
	{ "joinerror_bad_mask", "Cannot join to channel %_$0%_ %K(%nBad channel mask%K)", 1, { 0 } },
	{ "joinerror_unavail", "Cannot join to channel %_$0%_ %K(%nChannel is temporarily unavailable%K)", 1, { 0 } },
	{ "kick", "%c$0%n was kicked from %_$1%_ by %_$2%_ %K[%n$3%K]", 4, { 0, 0, 0, 0 } },
	{ "quit", "%c$0 %K[%n$1%K]%n has quit IRC %K[%n$2%K]", 3, { 0, 0, 0 } },
	{ "quit_once", "%_$3%_ %c$0 %K[%n$1%K]%n has quit IRC %K[%n$2%K]", 4, { 0, 0, 0, 0 } },
	{ "invite", "%_$0%_ invites you to %_$1", 2, { 0, 0 } },
	{ "inviting", "Inviting $0 to %_$1", 2, { 0, 0 } },
	{ "not_invited", "You have not been invited to a channel!", 0 },
	{ "names", "%K[%g%_Users%_%K(%g$0%K)]%n $1", 2, { 0, 0 } },
	{ "names_nick", "%K[%n%_$0%_$1%K] ", 2, { 0, 0 } },
	{ "endofnames", "%g%_$0%_%K:%n Total of %_$1%_ nicks %K[%n%_$2%_ ops, %_$3%_ voices, %_$4%_ normal%K]", 5, { 0, 1, 1, 1, 1 } },
	{ "channel_created", "Channel %_$0%_ created $1", 2, { 0, 0 } },
	{ "topic", "Topic for %c$0%K:%n $1", 2, { 0, 0 } },
	{ "no_topic", "No topic set for %c$0", 1, { 0 } },
	{ "new_topic", "%_$0%_ changed the topic of %c$1%n to%K:%n $2", 3, { 0, 0, 0 } },
	{ "topic_unset", "Topic unset by %_$0%_ on %c$1", 2, { 0, 0 } },
	{ "topic_info", "Topic set by %_$0%_ %K[%n$1%K]", 2, { 0, 0 } },
	{ "chanmode_change", "mode/%c$0 %K[%n$1%K]%n by %_$2", 3, { 0, 0, 0 } },
	{ "server_chanmode_change", "%RServerMode/%c$0 %K[%n$1%K]%n by %_$2", 3, { 0, 0, 0 } },
	{ "channel_mode", "mode/%c$0 %K[%n$1%K]", 2, { 0, 0 } },
	{ "bantype", "Ban type changed to %_$0", 1, { 0 } },
	{ "no_bans", "No bans in channel %_$0%_", 1, { 0 } },
	{ "banlist", "%_$0%_: ban %c$1", 2, { 0, 0 } },
	{ "banlist_long", "%_$0%_: ban %c$1 %K[%nby %_$2%_, $3 secs ago%K]", 4, { 0, 0, 0, 1 } },
	{ "ebanlist", "%_$0%_: ban exception %c$1", 2, { 0, 0 } },
	{ "ebanlist_long", "%_$0%_: ban exception %c$1 %K[%nby %_$2%_, $3 secs ago%K]", 4, { 0, 0, 0, 1 } },
	{ "invitelist", "%_$0%_: invite %c$1", 2, { 0, 0 } },
	{ "no_such_channel", "$0: No such channel", 1, { 0 } },
	{ "channel_synced", "Join to %_$0%_ was synced in %_$1%_ secs", 2, { 0, 2 } },
	{ "not_in_channels", "You are not on any channels", 0 },
	{ "current_channel", "Current channel $0", 1, { 0 } },
	{ "chanlist_header", "You are on the following channels:", 0 },
	{ "chanlist_line", "$[-10]0 %|+$1 ($2): $3", 4, { 0, 0, 0, 0 } },
	{ "chansetup_not_found", "Channel $0 not found", 2, { 0, 0 } },
	{ "chansetup_added", "Channel $0 saved", 2, { 0, 0 } },
	{ "chansetup_removed", "Channel $0 removed", 2, { 0, 0 } },
	{ "chansetup_header", "Channel         IRC net    Password   Settings", 0 },
	{ "chansetup_line", "$[15]0 %|$[10]1 $[10]2 $3", 4, { 0, 0, 0, 0 } },
	{ "chansetup_footer", "", 0 },

	/* ---- */
	{ NULL, "Nick", 0 },

	{ "usermode_change", "Mode change %K[%n%_$0%_%K]%n for user %c$1", 2, { 0, 0 } },
	{ "user_mode", "Your user mode is %K[%n%_$0%_%K]", 1, { 0 } },
	{ "away", "You have been marked as being away", 0 },
	{ "unaway", "You are no longer marked as being away", 0 },
	{ "nick_away", "$0 is away: $1", 2, { 0, 0 } },
	{ "no_such_nick", "$0: No such nick/channel", 1, { 0 } },
	{ "your_nick", "Your nickname is $0", 1, { 0 } },
	{ "your_nick_changed", "You're now known as %c$0", 1, { 0 } },
	{ "nick_changed", "%_$0%_ is now known as %c$1", 2, { 0, 0 } },
	{ "nick_in_use", "Nick %_$0%_ is already in use", 1, { 0 } },
	{ "nick_unavailable", "Nick %_$0%_ is temporarily unavailable", 1, { 0 } },
	{ "your_nick_owned", "Your nick is owned by %_$3%_ %K[%n$1@$2%K]", 4, { 0, 0, 0, 0 } },

	/* ---- */
	{ NULL, "Who queries", 0 },

	{ "whois", "%_$0%_ %K[%n$1@$2%K]%n%: ircname  : $3", 4, { 0, 0, 0, 0 } },
	{ "whowas", "%_$0%_ %K[%n$1@$2%K]%n%: ircname  : $3", 4, { 0, 0, 0, 0 } },
	{ "whois_idle", " idle     : $1 days $2 hours $3 mins $4 secs", 5, { 0, 1, 1, 1, 1 } },
	{ "whois_idle_signon", " idle     : $1 days $2 hours $3 mins $4 secs %K[%nsignon: $5%K]", 6, { 0, 1, 1, 1, 1, 0 } },
	{ "whois_server", " server   : $1 %K[%n$2%K]", 3, { 0, 0, 0 } },
	{ "whois_oper", "          : %_IRC operator%_", 1, { 0 } },
	{ "whois_registered", "          : has registered this nick", 1, { 0 } },
	{ "whois_channels", " channels : $1", 2, { 0, 0 } },
	{ "whois_away", " away     : $1", 2, { 0, 0 } },
	{ "end_of_whois", "End of WHOIS", 1, { 0 } },
	{ "end_of_whowas", "End of WHOWAS", 1, { 0 } },
	{ "whois_not_found", "There is no such nick $0", 1, { 0 } },
	{ "who", "$[-10]0 %|%_$[!9]1%_ $[!3]2 $[!2]3 $4@$5 %K(%W$6%K)", 7, { 0, 0, 0, 0, 0, 0, 0 } },
	{ "end_of_who", "End of /WHO list", 1, { 0 } },

	/* ---- */
	{ NULL, "Your messages", 0 },

	{ "own_msg", "%K<%n$2%W$0%K>%n %|$1", 3, { 0, 0, 0 } },
	{ "own_msg_channel", "%K<%n$3%W$0%K:%c$1%K>%n %|$2", 4, { 0, 0, 0, 0 } },
	{ "own_msg_private", "%K[%rmsg%K(%R$0%K)]%n $1", 2, { 0, 0 } },
	{ "own_msg_private_query", "%K<%W$2%K>%n %|$1", 3, { 0, 0, 0 } },
	{ "own_notice", "%K[%rnotice%K(%R$0%K)]%n $1", 2, { 0, 0 } },
	{ "own_me", "%W * $0%n $1", 2, { 0, 0 } },
	{ "own_ctcp", "%K[%rctcp%K(%R$0%K)]%n $1 $2", 3, { 0, 0, 0 } },
	{ "own_wall", "%K[%WWall%K/%c$0%K]%n $1", 2, { 0, 0 } },

	/* ---- */
	{ NULL, "Received messages", 0 },

	{ "pubmsg_me", "%K<%n$2%Y$0%K>%n %|$1", 3, { 0, 0, 0 } },
	{ "pubmsg_me_channel", "%K<%n$3%Y$0%K:%c$1%K>%n %|$2", 4, { 0, 0, 0, 0 } },
	{ "pubmsg_hilight", "%K<%n$3$0$1%K>%n %|$2", 4, { 0, 0, 0, 0 } },
	{ "pubmsg_hilight_channel", "%K<%n$4$0$1%K:%c$2%K>%n %|$3", 5, { 0, 0, 0, 0, 0 } },
	{ "pubmsg", "%K<%n$2$0%K>%n %|$1", 3, { 0, 0, 0 } },
	{ "pubmsg_channel", "%K<%n$3$0%K:%c$1%K>%n %|$2", 4, { 0, 0, 0, 0 } },
	{ "msg_private", "%K[%R$0%K(%r$1%K)]%n $2", 3, { 0, 0, 0 } },
	{ "msg_private_query", "%K<%R$0%K>%n %|$2", 3, { 0, 0, 0 } },
	{ "notice_server", "%g!$0%n $1", 2, { 0, 0 } },
	{ "notice_public", "%K-%M$0%K:%m$1%K-%n $2", 3, { 0, 0, 0 } },
	{ "notice_public_ops", "%K-%M$0%K:%m@$1%K-%n $2", 3, { 0, 0, 0 } },
	{ "notice_private", "%K-%M$0%K(%m$1%K)-%n $2", 3, { 0, 0, 0 } },
	{ "action_private", "%W (*) $0%n $2", 3, { 0, 0, 0 } },
	{ "action_private_query", "%W * $0%n $2", 3, { 0, 0, 0 } },
	{ "action_public", "%W * $0%n $1", 2, { 0, 0 } },
	{ "action_public_channel", "%W * $0%K:%c$1%n $2", 3, { 0, 0, 0 } },

	/* ---- */
	{ NULL, "CTCPs", 0 },

	{ "ctcp_reply", "CTCP %_$0%_ reply from %_$1%_%K:%n $2", 3, { 0, 0, 0 } },
	{ "ctcp_reply_channel", "CTCP %_$0%_ reply from %_$1%_ in channel %_$3%_%K:%n $2", 4, { 0, 0, 0, 0 } },
	{ "ctcp_ping_reply", "CTCP %_PING%_ reply from %_$0%_: $1.$2 seconds", 3, { 0, 2, 2 } },
	{ "ctcp_requested", "%g>>> %_$0%_ %K[%g$1%K] %grequested %_$2%_ from %_$3", 4, { 0, 0, 0, 0 } },

	/* ---- */
	{ NULL, "Other server events", 0 },

	{ "online", "Users online: %_$0", 1, { 0 } },
	{ "pong", "PONG received from $0: $1", 2, { 0, 0 } },
	{ "wallops", "%WWALLOP%n $0: $1", 2, { 0, 0 } },
	{ "action_wallops", "%WWALLOP * $0%n $1", 2, { 0, 0 } },
	{ "error", "%_ERROR%_ $0", 1, { 0 } },
	{ "unknown_mode", "Unknown mode character $0", 1, { 0 } },
	{ "not_chanop", "You're not channel operator in $0", 1, { 0 } },

	/* ---- */
	{ NULL, "Misc", 0 },

	{ "ignored", "Ignoring %_$1%_ from %_$0%_", 2, { 0, 0 } },
	{ "unignored", "Unignored %_$0%_", 1, { 0 } },
	{ "ignore_not_found", "%_$0%_ is not being ignored", 1, { 0 } },
	{ "ignore_no_ignores", "There are no ignores", 0 },
	{ "ignore_header", "Ignorance List:", 0 },
	{ "ignore_line", "$[-4]0 $1: $2 $3 $4", 4, { 1, 0, 0, 0 } },
	{ "ignore_footer", "", 0 },
	{ "talking_in", "You are now talking in %_$0%_", 1, { 0 } },
	{ "query_start", "Starting query with %_$0%_", 1, { 0 } },
	{ "no_query", "No query with %_$0%_", 1, { 0 } },
	{ "no_msgs_got", "You have not received a message from anyone yet", 0 },
	{ "no_msgs_sent", "You have not sent a message to anyone yet", 0 },

	{ NULL, NULL, 0 }
};
