/*
 dcc-resume.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "signals.h"
#include "commands.h"
#include "network.h"
#include "misc.h"

#include "dcc-file.h"
#include "dcc-get.h"
#include "dcc-send.h"
#include "dcc-chat.h"

static FILE_DCC_REC *dcc_resume_find(int type, const char *nick, int port)
{
	GSList *tmp;

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		FILE_DCC_REC *dcc = tmp->data;

		if (dcc->type == type && !dcc_is_connected(dcc) &&
		    dcc->port == port && g_strcasecmp(dcc->nick, nick) == 0)
			return dcc;
	}

	return NULL;
}

#define get_params_match_resume(params, pos) \
	(is_numeric(params[pos], '\0') && atol(params[pos]) < 65536 && \
	is_numeric(params[(pos)+1], '\0'))

/* Based on get_file_params_count() found in dcc-get.c. The main difference
   is represented by the number of params expected after the filename (2 at
   least). I've added this new routine to avoid possible troubles connected
   to relaxing the old checks done on DCC GET params to suite the ACCEPT/RESUME
   needs.
   */
int get_file_params_count_resume(char **params, int paramcount)
{
	int pos, best;

	if (*params[0] == '"') {
		/* quoted file name? */
		for (pos = 0; pos < paramcount-2; pos++) {
			if (params[pos][strlen(params[pos])-1] == '"' &&
			    get_params_match_resume(params, pos+1))
				return pos+1;
		}
	}

	best = paramcount-2;
	for (pos = paramcount-2; pos > 0; pos--) {
		if (get_params_match_resume(params, pos))
			best = pos;
	}

	return best;
}


static int dcc_ctcp_resume_parse(int type, const char *data, const char *nick,
				 FILE_DCC_REC **dcc, uoff_t *size, int *pasv_id)
{
	char **params;
	int paramcount, fileparams;
	int port;

	/* RESUME|ACCEPT <file name> <port> <size> */
	/* RESUME|ACCEPT <file name> 0 <size> <id> (passive protocol) */
	params = g_strsplit(data, " ", -1);
	paramcount = strarray_length(params);

	if (paramcount < 3)
		return 0;

	fileparams = get_file_params_count_resume(params, paramcount);
    
	if (paramcount >= fileparams + 2) {
		port = atoi(params[fileparams]);
		*size = str_to_uofft(params[fileparams+1]);
		*pasv_id = ((port == 0) && (paramcount == fileparams + 3)) ? atoi(params[fileparams+2]) : -1;
		*dcc = dcc_resume_find(type, nick, port);
		g_strfreev(params);

		/* If the ID is different then the DCC cannot be resumed */
		return ((*dcc != NULL) && ((*dcc)->pasv_id == *pasv_id));
	}
	g_strfreev(params);
	return FALSE;
}

static int dcc_resume_file_check(FILE_DCC_REC *dcc, IRC_SERVER_REC *server,
				 uoff_t size)
{
	if (size >= dcc->size) {
		/* whole file sent */
		dcc->starttime = time(NULL);
		dcc_reject(DCC(dcc), server);
	} else if (lseek(dcc->fhandle, (off_t)size, SEEK_SET) != (off_t)size) {
		/* error */
		dcc_reject(DCC(dcc), server);
	} else {
		dcc->transfd = dcc->skipped = size;
                return TRUE;
	}

	return FALSE;
}

/* CTCP: DCC RESUME - requesting to resume DCC SEND */
static void ctcp_msg_dcc_resume(IRC_SERVER_REC *server, const char *data,
				const char *nick, const char *addr,
				const char *target, DCC_REC *chat)
{
	FILE_DCC_REC *dcc;
        char *str;
	uoff_t size;
	int pasv_id = -1;

	if (!dcc_ctcp_resume_parse(DCC_SEND_TYPE, data, nick, &dcc, &size, &pasv_id)) {
		signal_emit("dcc error ctcp", 5, "RESUME", data,
			    nick, addr, target);
	} else if (dcc != NULL && dcc_resume_file_check(dcc, server, size)) {
		if (!dcc_is_passive(dcc)) {
			str = g_strdup_printf(DCC_SEND(dcc)->file_quoted ?
					      "DCC ACCEPT \"%s\" %d %"PRIuUOFF_T :
					      "DCC ACCEPT %s %d %"PRIuUOFF_T,
					      dcc->arg, dcc->port, dcc->transfd);
		} else {
			str = g_strdup_printf(DCC_SEND(dcc)->file_quoted ?
					      "DCC ACCEPT \"%s\" 0 %"PRIuUOFF_T" %d" :
					      "DCC ACCEPT %s 0 %"PRIuUOFF_T" %d",
					      dcc->arg, dcc->transfd, dcc->pasv_id);
		}
		dcc_ctcp_message(dcc->server, dcc->nick,
				 dcc->chat, FALSE, str);
		g_free(str);
	}
}

/* CTCP: DCC ACCEPT - accept resuming DCC GET */
static void ctcp_msg_dcc_accept(IRC_SERVER_REC *server, const char *data,
				const char *nick, const char *addr,
				const char *target, DCC_REC *chat)
{
	FILE_DCC_REC *dcc;
        uoff_t size;
	int pasv_id;

	if (!dcc_ctcp_resume_parse(DCC_GET_TYPE, data, nick, &dcc, &size, &pasv_id) ||
	    (dcc != NULL && DCC_GET(dcc)->get_type != DCC_GET_RESUME)) {
		signal_emit("dcc error ctcp", 5, "ACCEPT", data,
			    nick, addr, target);
	} else if (dcc != NULL && dcc_resume_file_check(dcc, server, size)) {
		if (!dcc_is_passive(dcc))
			dcc_get_connect(DCC_GET(dcc));
		else
			dcc_get_passive(DCC_GET(dcc));
	}
}

/* Resume a DCC GET */
static void dcc_send_resume(GET_DCC_REC *dcc)
{
        off_t pos;
	char *str;

        g_return_if_fail(dcc != NULL);

	dcc->file = dcc_get_download_path(dcc->arg);
	dcc->fhandle = open(dcc->file, O_WRONLY);
	if (dcc->fhandle == -1) {
		signal_emit("dcc error file open", 3, dcc->nick, dcc->file,
			    GINT_TO_POINTER(errno));
		return;
	}

	dcc->get_type = DCC_GET_RESUME;

	pos = lseek(dcc->fhandle, 0, SEEK_END);
	dcc->transfd = pos < 0 ? 0 : (uoff_t)pos;
	dcc->skipped = dcc->transfd;

	if (dcc->skipped == dcc->size) {
		/* already received whole file */
		dcc->starttime = time(NULL);
		dcc_reject(DCC(dcc), NULL);
	} else {
		if (!dcc_is_passive(dcc)) {
			str = g_strdup_printf(dcc->file_quoted ?
					      "DCC RESUME \"%s\" %d %"PRIuUOFF_T :
					      "DCC RESUME %s %d %"PRIuUOFF_T,
					      dcc->arg, dcc->port, dcc->transfd);
		} else {
			str = g_strdup_printf(dcc->file_quoted ?
					      "DCC RESUME \"%s\" 0 %"PRIuUOFF_T" %d" :
					      "DCC RESUME %s 0 %"PRIuUOFF_T" %d",
					      dcc->arg, dcc->transfd, dcc->pasv_id);
		}
		dcc_ctcp_message(dcc->server, dcc->nick,
				 dcc->chat, FALSE, str);
		g_free(str);
	}
}

/* SYNTAX: DCC RESUME [<nick> [<file>]] */
static void cmd_dcc_resume(const char *data)
{
	cmd_dcc_receive(data, dcc_send_resume, dcc_send_resume);
}

void dcc_resume_init(void)
{
	signal_add("ctcp msg dcc resume", (SIGNAL_FUNC) ctcp_msg_dcc_resume);
	signal_add("ctcp msg dcc accept", (SIGNAL_FUNC) ctcp_msg_dcc_accept);
	command_bind("dcc resume", NULL, (SIGNAL_FUNC) cmd_dcc_resume);
}

void dcc_resume_deinit(void)
{
	signal_remove("ctcp msg dcc resume", (SIGNAL_FUNC) ctcp_msg_dcc_resume);
	signal_remove("ctcp msg dcc accept", (SIGNAL_FUNC) ctcp_msg_dcc_accept);
	command_unbind("dcc resume", (SIGNAL_FUNC) cmd_dcc_resume);
}
