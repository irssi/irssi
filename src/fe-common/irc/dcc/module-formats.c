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
	{ "action_dcc_query", "{dccaction $0}$1", 2, { 0, 0 } },
	{ "own_dcc_query", "{ownmsgnick {dccownquerynick $0}}$2", 3, { 0, 0, 0 } },
	{ "dcc_msg_query", "{privmsgnick $0}$1", 2, { 0, 0 } },
	{ "dcc_ctcp", "{dcc >>> DCC CTCP {hilight $1} received from {hilight $0}: $2}", 3, { 0, 0, 0 } },
	{ "dcc_chat", "{dcc DCC CHAT from {nick $0} [$1 port $2]}", 3, { 0, 0, 1 } },
	{ "dcc_chat_channel", "{dcc DCC CHAT from {nick $0} [$1 port $2] requested in channel {channel $3}}", 4, { 0, 0, 1, 0 } },
	{ "dcc_chat_not_found", "{dcc No DCC CHAT connection open to {nick $0}}", 1, { 0 } },
	{ "dcc_chat_connected", "{dcc DCC CHAT connection with {nick $0} [$1 port $2] established}", 3, { 0, 0, 1 } },
	{ "dcc_chat_disconnected", "{dcc DCC lost chat to {nick $0}}", 1, { 0 } },
	{ "dcc_send", "{dcc DCC SEND from {nick $0} [$1 port $2]: $3 [$4]}", 5, { 0, 0, 1, 0, 0 } },
	{ "dcc_send_channel", "{dcc DCC SEND from {nick $0} [$1 port $2]: $3 [$4 bytes] requested in channel {channel $5}}", 6, { 0, 0, 1, 0, 0, 0 } },
	{ "dcc_send_exists", "{dcc DCC already sending file {dccfile $0} for {nick $1}}", 2, { 0, 0 } },
	{ "dcc_send_no_route", "{dcc DCC route lost to nick {nick $0} when trying to send file {dccfile $1}}", 2, { 0, 0 } },
	{ "dcc_send_not_found", "{dcc DCC not sending file {dccfile $1} to {nick $0}}", 2, { 0, 0 } },
	{ "dcc_send_file_open_error", "{dcc DCC can't open file {dccfile $0}: $1}", 2, { 0, 0 } },
	{ "dcc_send_connected", "{dcc DCC sending file {dccfile $0} for {nick $1} [$2 port $3]}", 4, { 0, 0, 0, 1 } },
	{ "dcc_send_complete", "{dcc DCC sent file {dccfile $0} [{hilight $1}] for {nick $2} in {hilight $3} [{hilight $4kB/s}]}", 5, { 0, 0, 0, 0, 3 } },
	{ "dcc_send_aborted", "{dcc DCC aborted sending file {dccfile $0} for {nick $1}}", 2, { 0, 0 } },
	{ "dcc_get_not_found", "{dcc DCC no file offered by {nick $0}}", 1, { 0 } },
	{ "dcc_get_connected", "{dcc DCC receiving file {dccfile $0} from {nick $1} [$2 port $3]}", 4, { 0, 0, 0, 1 } },
	{ "dcc_get_complete", "{dcc DCC received file {dccfile $0} [$1] from {nick $2} in {hilight $3} [$4kB/s]}", 5, { 0, 0, 0, 0, 3 } },
	{ "dcc_get_aborted", "{dcc DCC aborted receiving file {dccfile $0} from {nick $1}}", 2, { 0, 0 } },
	{ "dcc_get_write_error", "{dcc DCC error writing to file {dccfile $0}: {comment $1}", 2, { 0, 0 } },
	{ "dcc_unknown_ctcp", "{dcc DCC unknown ctcp {hilight $0} from {nick $1} [$2]}", 3, { 0, 0, 0 } },
	{ "dcc_unknown_reply", "{dcc DCC unknown reply {hilight $0} from {nick $1} [$2]}", 3, { 0, 0, 0 } },
	{ "dcc_unknown_type", "{dcc DCC unknown type {hilight $0}}", 1, { 0 } },
	{ "dcc_invalid_ctcp", "{dcc DCC received CTCP {hilight $0} with invalid parameters from {nick $1}}", 4, { 0, 0, 0, 0 } },
	{ "dcc_connect_error", "{dcc DCC can't connect to {hilight $0} port {hilight $1}}", 2, { 0, 1 } },
	{ "dcc_cant_create", "{dcc DCC can't create file {dccfile $0}: $1}", 2, { 0, 0 } },
	{ "dcc_rejected", "{dcc DCC $0 was rejected by {nick $1} [{hilight $2}]}", 3, { 0, 0, 0 } },
	{ "dcc_request_send", "{dcc DCC $0 request sent to {nick $1}: $2", 3, { 0, 0, 0 } },
	{ "dcc_close", "{dcc DCC $0 close for {nick $1} [{hilight $2}]}", 3, { 0, 0, 0 } },
	{ "dcc_lowport", "{dcc Warning: Port sent with DCC request is a lowport ({hilight $0, $1}) - this isn't normal. It is possible the address/port is faked (or maybe someone is just trying to bypass firewall)}", 2, { 1, 0 } },
	{ "dcc_list_header", "{dcc DCC connections}", 0 },
	{ "dcc_list_line_chat", "{dcc  $0 $1}", 2, { 0, 0 } },
	{ "dcc_list_line_file", "{dcc  $0 $1: %|$2 of $3 ($4%%) - $5kB/s - ETA $7 - $6}", 8, { 0, 0, 0, 0, 1, 3, 0, 0 } },
	{ "dcc_list_line_queued_send", "{dcc   - $0 $2 (queued)}", 3, { 0, 0, 0 } },
	{ "dcc_list_footer", "", 0 },
	{ "dcc_list_line_server", "{dcc  $0: Port($1) - Send($2) - Chat($3) - Fserve($4)}", 5, { 0, 1, 0, 0, 0 } },
	{ "dcc_server_started", "{dcc  DCC SERVER started on port {hilight $0}}", 1, { 1 } },
	{ "dcc_server_closed", "{dcc  DCC SERVER on port {hilight $0} closed}", 1, { 1 } },

	{ NULL, NULL, 0 }
};
