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

FORMAT_REC fecommon_irc_formats[] =
{
    { MODULE_NAME, N_("IRC"), 0 },

    /* ---- */
    { NULL, N_("Server"), 0 },

    { "lag_disconnected", N_("No PONG reply from server %_$0%_ in $1 seconds, disconnecting"), 2, { 0, 1 } },
    { "disconnected", N_("Disconnected from %_$0%_ %K[%n$1%K]"), 2, { 0, 0 } },
    { "server_list", N_("%_$0%_: $1:$2 ($3)"), 5, { 0, 0, 1, 0, 0 } },
    { "server_lookup_list", N_("%_$0%_: $1:$2 ($3) (connecting...)"), 5, { 0, 0, 1, 0, 0 } },
    { "server_reconnect_list", N_("%_$0%_: $1:$2 ($3) ($5 left before reconnecting)"), 6, { 0, 0, 1, 0, 0, 0 } },
    { "server_reconnect_removed", N_("Removed reconnection to server %_$0%_ port %_$1%_"), 3, { 0, 1, 0 } },
    { "server_reconnect_not_found", N_("Reconnection tag %_$0%_ not found"), 1, { 0 } },
    { "query_server_changed", N_("Query with %_$2%_ changed to server %_$1%_"), 3, { 0, 0, 0 } },

    /* ---- */
    { NULL, N_("Channels"), 0 },

    { "join", N_("%c%_$0%_ %K[%c$1%K]%n has joined %_$2"), 3, { 0, 0, 0 } },
    { "part", N_("%c$0 %K[%n$1%K]%n has left %_$2%_ %K[%n$3%K]"), 4, { 0, 0, 0, 0 } },
    { "joinerror_toomany", N_("Cannot join to channel %_$0%_ %K(%nYou have joined to too many channels%K)"), 1, { 0 } },
    { "joinerror_full", N_("Cannot join to channel %_$0%_ %K(%nChannel is full%K)"), 1, { 0 } },
    { "joinerror_invite", N_("Cannot join to channel %_$0%_ %K(%nYou must be invited%K)"), 1, { 0 } },
    { "joinerror_banned", N_("Cannot join to channel %_$0%_ %K(%nYou are banned%K)"), 1, { 0 } },
    { "joinerror_bad_key", N_("Cannot join to channel %_$0%_ %K(%nBad channel key%K)"), 1, { 0 } },
    { "joinerror_bad_mask", N_("Cannot join to channel %_$0%_ %K(%nBad channel mask%K)"), 1, { 0 } },
    { "joinerror_unavail", N_("Cannot join to channel %_$0%_ %K(%nChannel is temporarily unavailable%K)"), 1, { 0 } },
    { "kick", N_("%c$0%n was kicked from %_$1%_ by %_$2%_ %K[%n$3%K]"), 4, { 0, 0, 0, 0 } },
    { "quit", N_("%c$0 %K[%n$1%K]%n has quit IRC %K[%n$2%K]"), 3, { 0, 0, 0 } },
    { "quit_once", N_("%_$3%_ %c$0 %K[%n$1%K]%n has quit IRC %K[%n$2%K]"), 4, { 0, 0, 0, 0 } },
    { "invite", N_("%_$0%_ invites you to %_$1"), 2, { 0, 0 } },
    { "inviting", N_("Inviting $0 to %_$1"), 2, { 0, 0 } },
    { "not_invited", N_("You have not been invited to a channel!"), 0 },
    { "names", N_("%K[%g%_Users%_%K(%g$0%K)]%n $1"), 2, { 0, 0 } },
    { "endofnames", N_("%g%_$0%_%K:%n Total of %_$1%_ nicks %K[%n%_$2%_ ops, %_$3%_ voices, %_$4%_ normal%K]"), 5, { 0, 1, 1, 1, 1 } },
    { "channel_created", N_("Channel %_$0%_ created $1"), 2, { 0, 0 } },
    { "topic", N_("Topic for %c$0%K:%n $1"), 2, { 0, 0 } },
    { "no_topic", N_("No topic set for %c$0"), 1, { 0 } },
    { "new_topic", N_("%_$0%_ changed the topic of %c$1%n to%K:%n $2"), 3, { 0, 0, 0 } },
    { "topic_unset", N_("Topic unset by %_$0%_ on %c$1"), 2, { 0, 0 } },
    { "topic_info", N_("Topic set by %_$0%_ %K[%n$1%K]"), 2, { 0, 0 } },
    { "chanmode_change", N_("mode/%c$0 %K[%n$1%K]%n by %_$2"), 3, { 0, 0, 0 } },
    { "server_chanmode_change", N_("%RServerMode/%c$0 %K[%n$1%K]%n by %_$2"), 3, { 0, 0, 0 } },
    { "channel_mode", N_("mode/%c$0 %K[%n$1%K]"), 2, { 0, 0 } },
    { "bantype", N_("Ban type changed to %_$0"), 1, { 0 } },
    { "banlist", N_("%_$0%_: ban %c$1"), 2, { 0, 0 } },
    { "banlist_long", N_("%_$0%_: ban %c$1 %K[%nby %_$2%_, $3 secs ago%K]"), 4, { 0, 0, 0, 1 } },
    { "ebanlist", N_("%_$0%_: ban exception %c$1"), 2, { 0, 0 } },
    { "ebanlist_long", N_("%_$0%_: ban exception %c$1 %K[%nby %_$2%_, $3 secs ago%K]"), 4, { 0, 0, 0, 1 } },
    { "invitelist", N_("%_$0%_: invite %c$1"), 2, { 0, 0 } },
    { "no_such_channel", N_("$0: No such channel"), 1, { 0 } },
    { "not_in_channels", N_("You are not on any channels"), 0 },
    { "current_channel", N_("Current channel $0"), 1, { 0 } },
    { "chanlist_header", N_("You are on the following channels:"), 0 },
    { "chanlist_line", N_("$[-10]0 %|+$1 ($2): $3"), 4, { 0, 0, 0, 0 } },
    { "channel_synced", N_("Join to %_$0%_ was synced in %_$1%_ secs"), 2, { 0, 2 } },

    /* ---- */
    { NULL, N_("Nick"), 0 },

    { "usermode_change", N_("Mode change %K[%n%_$0%_%K]%n for user %c$1"), 2, { 0, 0 } },
    { "user_mode", N_("Your user mode is %K[%n%_$0%_%K]"), 1, { 0 } },
    { "away", N_("You have been marked as being away"), 0 },
    { "unaway", N_("You are no longer marked as being away"), 0 },
    { "nick_away", N_("$0 is away: $1"), 2, { 0, 0 } },
    { "no_such_nick", N_("$0: No such nick/channel"), 1, { 0 } },
    { "your_nick", N_("Your nickname is $0"), 1, { 0 } },
    { "your_nick_changed", N_("You're now known as %c$0"), 1, { 0 } },
    { "nick_changed", N_("%_$0%_ is now known as %c$1"), 2, { 0, 0 } },
    { "nick_in_use", N_("Nick %_$0%_ is already in use"), 1, { 0 } },
    { "nick_unavailable", N_("Nick %_$0%_ is temporarily unavailable"), 1, { 0 } },
    { "your_nick_owned", N_("Your nick is owned by %_$3%_ %K[%n$1@$2%K]"), 4, { 0, 0, 0, 0 } },

    /* ---- */
    { NULL, N_("Who queries"), 0 },

    { "whois", N_("%_$0%_ %K[%n$1@$2%K]%n%: ircname  : $3"), 4, { 0, 0, 0, 0 } },
    { "whois_idle", N_(" idle     : $1 hours $2 mins $3 secs"), 4, { 0, 1, 1, 1 } },
    { "whois_idle_signon", N_(" idle     : $1 hours $2 mins $3 secs %K[%nsignon: $4%K]"), 5, { 0, 1, 1, 1, 0 } },
    { "whois_server", N_(" server   : $1 %K[%n$2%K]"), 3, { 0, 0, 0 } },
    { "whois_oper", N_("          : %_IRC operator%_"), 1, { 0 } },
    { "whois_channels", N_(" channels : $1"), 2, { 0, 0 } },
    { "whois_away", N_(" away     : $1"), 2, { 0, 0 } },
    { "end_of_whois", N_("End of WHOIS"), 1, { 0 } },
    { "who", N_("$[-10]0 %|%_$[!9]1%_ $[!3]2 $[!2]3 $4@$5 %K(%W$6%K)"), 7, { 0, 0, 0, 0, 0, 0, 0 } },
    { "end_of_who", N_("End of /WHO list"), 1, { 0 } },

    /* ---- */
    { NULL, N_("Your messages"), 0 },

    { "own_msg", N_("%K<%n$2%W$0%K>%n %|$1"), 3, { 0, 0, 0 } },
    { "own_msg_channel", N_("%K<%n$3%W$0%K:%c$1%K>%n %|$2"), 4, { 0, 0, 0, 0 } },
    { "own_msg_private", N_("%K[%rmsg%K(%R$0%K)]%n $1"), 2, { 0, 0 } },
    { "own_msg_private_query", N_("%K<%W$2%K>%n %|$1"), 3, { 0, 0, 0 } },
    { "own_notice", N_("%K[%rnotice%K(%R$0%K)]%n $1"), 2, { 0, 0 } },
    { "own_me", N_("%W * $0%n $1"), 2, { 0, 0 } },
    { "own_ctcp", N_("%K[%rctcp%K(%R$0%K)]%n $1 $2"), 3, { 0, 0, 0 } },

    /* ---- */
    { NULL, N_("Received messages"), 0 },

    { "pubmsg_me", N_("%K<%n$2%Y$0%K>%n %|$1"), 3, { 0, 0, 0 } },
    { "pubmsg_me_channel", N_("%K<%n$3%Y$0%K:%c$1%K>%n %|$2"), 4, { 0, 0, 0, 0 } },
    { "pubmsg_hilight", N_("%K<%n$3$0$1%K>%n %|$2"), 4, { 0, 0, 0, 0 } },
    { "pubmsg_hilight_channel", N_("%K<%n$4$0$1%K:%c$2%K>%n %|$3"), 5, { 0, 0, 0, 0, 0 } },
    { "pubmsg", N_("%K<%n$2$0%K>%n %|$1"), 3, { 0, 0, 0 } },
    { "pubmsg_channel", N_("%K<%n$3$0%K:%c$1%K>%n %|$2"), 4, { 0, 0, 0, 0 } },
    { "msg_private", N_("%K[%R$0%K(%r$1%K)]%n $2"), 3, { 0, 0, 0 } },
    { "msg_private_query", N_("%K<%R$0%K>%n %|$2"), 3, { 0, 0, 0 } },
    { "notice_server", N_("%g!$0%n $1"), 2, { 0, 0 } },
    { "notice_public", N_("%K-%M$0%K:%m$1%K-%n $2"), 3, { 0, 0, 0 } },
    { "notice_public_ops", N_("%K-%M$0%K:%m@$1%K-%n $2"), 3, { 0, 0, 0 } },
    { "notice_private", N_("%K-%M$0%K(%m$1%K)-%n $2"), 3, { 0, 0, 0 } },
    { "action_private", N_("%W (*) $0%n $2"), 3, { 0, 0, 0 } },
    { "action_private_query", N_("%W * $0%n $2"), 3, { 0, 0, 0 } },
    { "action_public", N_("%W * $0%n $1"), 2, { 0, 0 } },
    { "action_public_channel", N_("%W * $0%K:%c$1%n $2"), 3, { 0, 0, 0 } },

    /* ---- */
    { NULL, N_("CTCPs"), 0 },

    { "ctcp_reply", N_("CTCP %_$0%_ reply from %_$1%_%K:%n $2"), 3, { 0, 0, 0 } },
    { "ctcp_ping_reply", N_("CTCP %_PING%_ reply from %_$0%_: $1.$2 seconds"), 3, { 0, 2, 2 } },
    { "ctcp_requested", N_("%g>>> %_$0%_ %K[%g$1%K] %grequested %_$2%_ from %_$3"), 4, { 0, 0, 0, 0 } },

    /* ---- */
    { NULL, N_("Other server events"), 0 },

    { "online", N_("Users online: %_$0"), 1, { 0 } },
    { "pong", N_("PONG received from $0: $1"), 2, { 0, 0 } },
    { "wallops", N_("%WWALLOP%n $0: $1"), 2, { 0, 0 } },
    { "action_wallops", N_("%WWALLOP * $0%n $1"), 2, { 0, 0 } },
    { "error", N_("%_ERROR%_ $0"), 1, { 0 } },
    { "unknown_mode", N_("Unknown mode character $0"), 1, { 0 } },
    { "not_chanop", N_("You're not channel operator in $0"), 1, { 0 } },

    /* ---- */
    { NULL, N_("Misc"), 0 },

    { "ignored", N_("Ignoring %_$1%_ from %_$0%_"), 2, { 0, 0 } },
    { "unignored", N_("Unignored %_$0%_"), 1, { 0 } },
    { "ignore_not_found", N_("%_$0%_ is not being ignored"), 1, { 0 } },
    { "ignore_no_ignores", N_("There are no ignores"), 0 },
    { "ignore_header", N_("Ignorance List:"), 0 },
    { "ignore_line", N_("$[-4]0 $1: $2 $3 $4"), 5, { 1, 0, 0, 0, 0 } },
    { "ignore_footer", N_(""), 0 },
    { "talking_in", N_("You are now talking in %_$0%_"), 1, { 0 } },
    { "no_query", N_("No query with %_$0%_"), 1, { 0 } },
    { "no_msgs_got", N_("You have not received a message from anyone yet"), 0 },
    { "no_msgs_sent", N_("You have not sent a message to anyone yet"), 0 }
};
