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
#include "formats.h"

FORMAT_REC fecommon_irc_dcc_formats[] = {
	{ MODULE_NAME, "IRC", 0 },

	/* ---- */
	{ NULL, "DCC", 0 },

	{ "own_dcc", "{dccownmsg dcc {dccownnick $1}}$2", 3, { 0, 0, 0 } },
	{ "own_dcc_action", "{dccownaction_target $0 $1}$2", 3, { 0, 0, 0 } },
	{ "own_dcc_action_query", "{dccownaction $0}$2", 3, { 0, 0, 0 } },
	{ "own_dcc_ctcp", "{ownctcp ctcp $0}$1 $2", 3, { 0, 0, 0 } },
	{ "dcc_msg", "{dccmsg dcc $0}$1", 2, { 0, 0 } },
	{ "action_dcc", "{dccaction $0}$1", 2, { 0, 0 } },
	{ "own_dcc_query", "{ownmsgnick {ownnick $0}}$2", 3, { 0, 0, 0 } },
	{ "dcc_msg_query", "{privmsgnick $0}$1", 2, { 0, 0 } },
	{ "dcc_ctcp", "{dcc >>> DCC CTCP received from {hilight $0}: $1}", 2, { 0, 0 } },
	{ "dcc_chat", "{dcc DCC CHAT from {nick $0} [$1 port $2]}", 3, { 0, 0, 1 } },
	{ "dcc_chat_channel", "{dcc DCC CHAT from {nick $0} [$1 port $2] requested in channel {channel $3}}", 4, { 0, 0, 1, 0 } },
	{ "dcc_chat_not_found", "{dcc No DCC CHAT connection open to {nick $0}}", 1, { 0 } },
	{ "dcc_chat_connected", "{dcc DCC CHAT connection with {nick $0} [$1 port $2] established}", 3, { 0, 0, 1 } },
	{ "dcc_chat_disconnected", "{dcc DCC lost chat to {nick $0}}", 1, { 0 } },
	{ "dcc_send", "{dcc DCC SEND from {nick $0} [$1 port $2]: $3 [$4 bytes]}", 5, { 0, 0, 1, 0, 2 } },
	{ "dcc_send_channel", "{dcc DCC SEND from {nick $0} [$1 port $2]: $3 [$4 bytes] requested in channel {channel $5}}", 6, { 0, 0, 1, 0, 2, 0 } },
	{ "dcc_send_exists", "{dcc DCC already sending file {dccfile $0} for {nick $1}}", 2, { 0, 0 } },
	{ "dcc_send_not_found", "{dcc DCC not sending file {dccfile $1} to {nick $0}}", 2, { 0, 0 } },
	{ "dcc_send_file_not_found", "{dcc DCC file not found: {dccfile $0}}", 1, { 0 } },
	{ "dcc_send_connected", "{dcc DCC sending file {dccfile $0} for {nick $1} [$2 port $3]}", 4, { 0, 0, 0, 1 } },
	{ "dcc_send_complete", "{dcc DCC sent file {dccfile $0} [{hilight $1}kb] for {nick $2} in {hilight $3} secs [{hilight $4kb/s}]}", 5, { 0, 2, 0, 2, 3 } },
	{ "dcc_send_aborted", "{dcc DCC aborted sending file {dccfile $0} for {nick $1}}", 2, { 0, 0 } },
	{ "dcc_get_not_found", "{dcc DCC no file offered by {nick $0}}", 1, { 0 } },
	{ "dcc_get_connected", "{dcc DCC receiving file {dccfile $0} from {nick $1} [$2 port $3]}", 4, { 0, 0, 0, 1 } },
	{ "dcc_get_complete", "{dcc DCC received file {dccfile $0} [$1kb] from {nick $2} in {hilight $3} secs [$4kb/s]}", 5, { 0, 2, 0, 2, 3 } },
	{ "dcc_get_aborted", "{dcc DCC aborted receiving file {dccfile $0} from {nick $1}}", 2, { 0, 0 } },
	{ "dcc_unknown_ctcp", "{dcc DCC unknown ctcp {hilight $0} from {nick $1} [$2]}", 3, { 0, 0, 0 } },
	{ "dcc_unknown_reply", "{dcc DCC unknown reply {hilight $0} from {nick $1} [$2]}", 3, { 0, 0, 0 } },
	{ "dcc_unknown_type", "{dcc DCC unknown type {hilight $0}}", 1, { 0 } },
	{ "dcc_invalid_ctcp", "{dcc DCC received CTCP {hilight $0} with invalid parameters from {nick $1}}", 4, { 0, 0, 0, 0 } },
	{ "dcc_connect_error", "{dcc DCC can't connect to {hilight $0} port {hilight $1}}", 2, { 0, 1 } },
	{ "dcc_cant_create", "{dcc DCC can't create file {dccfile $0}}", 1, { 0 } },
	{ "dcc_rejected", "{dcc DCC $0 was rejected by {nick $1} [{hilight $2}]}", 3, { 0, 0, 0 } },
	{ "dcc_close", "{dcc DCC $0 close for {nick $1} [{hilight $2}]}", 3, { 0, 0, 0 } },
	{ "dcc_lowport", "{dcc Warning: Port sent with DCC request is a lowport ({hilight $0, $1}) - this isn't normal. It is possible the address/port is faked (or maybe someone is just trying to bypass firewall)}", 2, { 1, 0 } },
	{ "dcc_list_header", "{dcc DCC connections}", 0 },
	{ "dcc_list_line_chat", "{dcc  $0 $1}", 2, { 0, 0 } },
	{ "dcc_list_line_file", "{dcc  $0 $1: $2k of $3k ($4%%) - $5kB/s - $6}", 7, { 0, 0, 2, 2, 1, 3, 0 } },
	{ "dcc_list_footer", "", 0 },

	{ NULL, NULL, 0 }
};
