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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

static int dcc_ctcp_resume_parse(int type, const char *data, const char *nick,
				 FILE_DCC_REC **dcc, uoff_t *size)
{
	char **params;
	int paramcount;
        int port;

	/* RESUME|ACCEPT <file name> <port> <size> */
	params = g_strsplit(data, " ", -1);
	paramcount = strarray_length(params);

	if (paramcount >= 3) {
		port = atoi(params[paramcount-2]);
		*size = str_to_uofft(params[paramcount-1]);

		*dcc = dcc_resume_find(type, nick, port);
	}
	g_strfreev(params);
	return paramcount >= 3;
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

	if (!dcc_ctcp_resume_parse(DCC_SEND_TYPE, data, nick, &dcc, &size)) {
		signal_emit("dcc error ctcp", 5, "RESUME", data,
			    nick, addr, target);
	} else if (dcc != NULL && dcc_resume_file_check(dcc, server, size)) {
		str = g_strdup_printf(DCC_SEND(dcc)->file_quoted ?
				      "DCC ACCEPT \"%s\" %d %"PRIuUOFF_T :
				      "DCC ACCEPT %s %d %"PRIuUOFF_T,
				      dcc->arg, dcc->port, dcc->transfd);
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

	if (!dcc_ctcp_resume_parse(DCC_GET_TYPE, data, nick, &dcc, &size) ||
	    (dcc != NULL && DCC_GET(dcc)->get_type != DCC_GET_RESUME)) {
		signal_emit("dcc error ctcp", 5, "ACCEPT", data,
			    nick, addr, target);
	} else if (dcc != NULL && dcc_resume_file_check(dcc, server, size))
		dcc_get_connect(DCC_GET(dcc));
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
		str = g_strdup_printf(dcc->file_quoted ?
				      "DCC RESUME \"%s\" %d %"PRIuUOFF_T :
				      "DCC RESUME %s %d %"PRIuUOFF_T,
				      dcc->arg, dcc->port, dcc->transfd);
		dcc_ctcp_message(dcc->server, dcc->nick,
				 dcc->chat, FALSE, str);
		g_free(str);
	}
}

/* SYNTAX: DCC RESUME [<nick> [<file>]] */
static void cmd_dcc_resume(const char *data)
{
	cmd_dcc_receive(data, dcc_send_resume);
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
