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

#include "dcc-get.h"

static DCC_REC *dcc_resume_find(int type, const char *nick, int port)
{
	GSList *tmp;

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->type == type && !dcc_is_connected(dcc) &&
		    dcc->port == port && g_strcasecmp(dcc->nick, nick) == 0)
			return dcc;
	}

	return NULL;
}

static int dcc_ctcp_resume_parse(int type, const char *data, const char *nick,
				 DCC_REC **dcc, long *size)
{
	char **params;
	int paramcount;
        int port;

	/* RESUME|ACCEPT <file name> <port> <size> */
	params = g_strsplit(data, " ", -1);
	paramcount = strarray_length(params);

	if (paramcount >= 3) {
		port = atoi(params[paramcount-2]);
		*size = atol(params[paramcount-1]);

		type = type == DCC_TYPE_RESUME ? DCC_TYPE_SEND : DCC_TYPE_GET;
		*dcc = dcc_resume_find(type, nick, port);
	}
	g_strfreev(params);
	return paramcount >= 3;
}

static int dcc_resume_file_check(DCC_REC *dcc, IRC_SERVER_REC *server,
				 long size)
{
	if (lseek(dcc->fhandle, 0, SEEK_END) == dcc->size) {
		/* whole file sent */
		dcc->starttime = time(NULL);
		dcc_reject(dcc, server);
	} else if (lseek(dcc->fhandle, size, SEEK_SET) != size) {
		/* error, or trying to seek after end of file */
		dcc_reject(dcc, server);
	} else {
		dcc->transfd = dcc->skipped = size;
                return TRUE;
	}

	return FALSE;
}

/* CTCP: DCC RESUME */
static void ctcp_msg_dcc_resume(IRC_SERVER_REC *server, const char *data,
				const char *nick, const char *addr,
				const char *target, DCC_REC *chat)
{
	DCC_REC *dcc;
        char *str;
        long size;

	if (!dcc_ctcp_resume_parse(DCC_TYPE_RESUME, data, nick, &dcc, &size)) {
		signal_emit("dcc error ctcp", 5, "RESUME", data,
			    nick, addr, target);
	} else if (dcc != NULL && dcc_resume_file_check(dcc, server, size)) {
		str = g_strdup_printf(dcc->file_quoted ?
				      "DCC ACCEPT \"%s\" %d %lu" :
				      "DCC ACCEPT %s %d %lu",
				      dcc->arg, dcc->port, dcc->transfd);
		dcc_ctcp_message(dcc->server, dcc->nick,
				 dcc->chat, FALSE, str);
		g_free(str);
	}
}

/* CTCP: DCC ACCEPT */
static void ctcp_msg_dcc_accept(IRC_SERVER_REC *server, const char *data,
				const char *nick, const char *addr,
				const char *target, DCC_REC *chat)
{
	DCC_REC *dcc;
        long size;

	if (!dcc_ctcp_resume_parse(DCC_TYPE_ACCEPT, data, nick, &dcc, &size) ||
	    (dcc != NULL && dcc->get_type != DCC_GET_RESUME)) {
		signal_emit("dcc error ctcp", 5, "ACCEPT", data,
			    nick, addr, target);
	} else if (dcc != NULL && dcc_resume_file_check(dcc, server, size))
		dcc_get_connect(dcc);
}

static void dcc_send_resume(DCC_REC *dcc)
{
	char *str;

	g_return_if_fail(dcc != NULL);

	dcc->file = dcc_get_download_path(dcc->arg);
	dcc->fhandle = open(dcc->file, O_WRONLY);
	if (dcc->fhandle == -1) {
		signal_emit("dcc error file not found", 2, dcc, dcc->file);
		return;
	}

	dcc->get_type = DCC_GET_RESUME;

	dcc->transfd = lseek(dcc->fhandle, 0, SEEK_END);
	if (dcc->transfd < 0) dcc->transfd = 0;
	dcc->skipped = dcc->transfd;

	if (dcc->skipped == dcc->size) {
		/* already received whole file */
		dcc->starttime = time(NULL);
		dcc_reject(dcc, NULL);
	} else {
		str = g_strdup_printf(dcc->file_quoted ?
				      "DCC RESUME \"%s\" %d %lu" :
				      "DCC RESUME %s %d %lu",
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
