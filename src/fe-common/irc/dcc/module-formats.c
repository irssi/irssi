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

FORMAT_REC fecommon_irc_dcc_formats[] =
{
    { MODULE_NAME, N_("IRC"), 0 },

    /* ---- */
    { NULL, N_("DCC"), 0 },

    { "own_dcc", N_("%K[%rdcc%K(%R$0%K)]%n $1"), 2, { 0, 0 } },
    { "dcc_msg", N_("%K[%G$0%K(%gdcc%K)]%n $1"), 2, { 0, 0 } },
    { "action_dcc", N_("%W (*dcc*) $0%n $1"), 2, { 0, 0 } },
    { "dcc_ctcp", N_("%g>>> DCC CTCP received from %_$0%_%K: %g$1"), 2, { 0, 0 } },
    { "dcc_chat", N_("%gDCC CHAT from %_$0%_ %K[%g$1 port $2%K]"), 3, { 0, 0, 1 } },
    { "dcc_chat_not_found", N_("%gNo DCC CHAT connection open to %_$0"), 1, { 0 } },
    { "dcc_chat_connected", N_("%gDCC %_CHAT%_ connection with %_$0%_ %K%K[%g$1 port $2%K]%g established"), 3, { 0, 0, 1 } },
    { "dcc_chat_disconnected", N_("%gDCC lost chat to %_$0"), 1, { 0 } },
    { "dcc_send", N_("%gDCC SEND from %_$0%_ %K[%g$1 port $2%K]: %g$3 %K[%g$4 bytes%K]"), 5, { 0, 0, 1, 0, 2 } },
    { "dcc_send_exists", N_("%gDCC already sending file %G$0%g for %_$1%_"), 2, { 0, 0 } },
    { "dcc_send_not_found", N_("%gDCC not sending file %G$1%g to %_$0"), 2, { 0, 0 } },
    { "dcc_send_file_not_found", N_("%gDCC file not found: %G$0%g"), 1, { 0 } },
    { "dcc_send_connected", N_("%gDCC sending file %G$0%g for %_$1%_ %K[%g$2 port $3%K]"), 4, { 0, 0, 0, 1 } },
    { "dcc_send_complete", N_("%gDCC sent file $0 %K[%g%_$1%_kb%K]%g for %_$2%_ in %_$3%_ secs %K[%g%_$4kb/s%_%K]"), 5, { 0, 2, 0, 2, 3 } },
    { "dcc_send_aborted", N_("%gDCC aborted sending file $0 for %_$1%_"), 2, { 0, 0 } },
    { "dcc_get_not_found", N_("%gDCC no file offered by %_$0"), 1, { 0 } },
    { "dcc_get_connected", N_("%gDCC receiving file %G$0%g from %_$1%_ %K[%g$2 port $3%K]"), 4, { 0, 0, 0, 1 } },
    { "dcc_get_complete", N_("%gDCC received file %G$0%g %K[%g$1kb%K]%g from %_$2%_ in %_$3%_ secs %K[%g$4kb/s%K]"), 5, { 0, 2, 0, 2, 3 } },
    { "dcc_get_aborted", N_("%gDCC aborted receiving file $0 from %_$1%_"), 2, { 0, 0 } },
    { "dcc_unknown_ctcp", N_("%gDCC unknown ctcp %G$0%g from %_$1%_ %K[%g$2%K]"), 3, { 0, 0, 0 } },
    { "dcc_unknown_reply", N_("%gDCC unknown reply %G$0%g from %_$1%_ %K[%g$2%K]"), 3, { 0, 0, 0 } },
    { "dcc_unknown_type", N_("%gDCC unknown type %_$0"), 1, { 0 } },
    { "dcc_connect_error", N_("%gDCC can't connect to %_$0%_ port %_$1"), 2, { 0, 1 } },
    { "dcc_cant_create", N_("%gDCC can't create file %G$0%g"), 1, { 0 } },
    { "dcc_rejected", N_("%gDCC %G$0%g was rejected by %_$1%_ %K[%G$2%K]"), 3, { 0, 0, 0 } },
    { "dcc_close", N_("%gDCC %G$0%g close for %_$1%_ %K[%G$2%K]"), 3, { 0, 0, 0 } }
};
