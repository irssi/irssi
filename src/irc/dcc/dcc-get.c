/*
 dcc-get.c : irssi

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
#include "settings.h"

#include "servers-setup.h"
#include "dcc-get.h"

static int dcc_file_create_mode;

char *dcc_get_download_path(const char *fname)
{
	char *str, *downpath;

	downpath = convert_home(settings_get_str("dcc_download_path"));
	str = g_strconcat(downpath, G_DIR_SEPARATOR_S, g_basename(fname), NULL);
	g_free(downpath);

	return str;
}

static char *dcc_get_rename_file(const char *fname)
{
	GString *newname;
	struct stat statbuf;
	char *ret;
	int num;

	newname = g_string_new(NULL);
	num = 1;
	do {
		g_string_sprintf(newname, "%s.%d", fname, num);
		num++;
	} while (stat(newname->str, &statbuf) == 0);

	ret = newname->str;
	g_string_free(newname, FALSE);
	return ret;
}

static void sig_dccget_send(DCC_REC *dcc);

void dcc_get_send_received(DCC_REC *dcc)
{
	guint32 recd;

	recd = (guint32) htonl(dcc->transfd);
	memcpy(dcc->count_buf, &recd, 4);

	dcc->count_pos =
		net_transmit(dcc->handle, dcc->count_buf+dcc->count_pos,
			     4-dcc->count_pos);
	if (dcc->count_pos == 4) dcc->count_pos = 0;

	/* count_pos might be -1 here. if this happens, the
	   count_buf should be re-sent.. also, if it's 1, 2 or 3, the
	   last 1-3 bytes should be sent later. these happen probably
	   never, but I just want to do it right.. :) */
	if (dcc->tagwrite == -1) {
		dcc->tagwrite = g_input_add(dcc->handle, G_INPUT_WRITE,
					    (GInputFunction) sig_dccget_send,
					    dcc);
	}
}

/* input function: DCC GET is free to send data */
static void sig_dccget_send(DCC_REC *dcc)
{
	guint32 recd;
	int ret;

	if (dcc->count_pos != 0) {
		ret = net_transmit(dcc->handle, dcc->count_buf+dcc->count_pos,
				   4-dcc->count_pos);

		if (dcc->count_pos <= 0)
			dcc->count_pos = ret;
		else if (ret > 0)
			dcc->count_pos += ret;

		if (dcc->count_pos == 4) dcc->count_pos = 0;

	}

	if (dcc->count_pos == 0) {
		g_source_remove(dcc->tagwrite);
                dcc->tagwrite = -1;
	}

	memcpy(&recd, dcc->count_buf, 4);
	if (recd != (guint32) htonl(dcc->transfd))
                dcc_get_send_received(dcc);
}

/* input function: DCC GET received data */
static void sig_dccget_receive(DCC_REC *dcc)
{
	int ret;

	g_return_if_fail(dcc != NULL);

	for (;;) {
		ret = net_receive(dcc->handle, dcc->databuf, dcc->databufsize);
		if (ret == 0) break;

		if (ret < 0) {
			/* socket closed - transmit complete,
			   or other side died.. */
			signal_emit("dcc closed", 1, dcc);
			dcc_destroy(dcc);
			return;
		}

		write(dcc->fhandle, dcc->databuf, ret);
		dcc->transfd += ret;
	}

	/* send number of total bytes received */
	if (dcc->count_pos <= 0)
		dcc_get_send_received(dcc);

	signal_emit("dcc transfer update", 1, dcc);
}

/* callback: net_connect() finished for DCC GET */
static void sig_dccget_connected(DCC_REC *dcc)
{
	struct stat statbuf;
	char *fname;

	g_return_if_fail(dcc != NULL);

	if (net_geterror(dcc->handle) != 0) {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(dcc);
		return;
	}

	g_source_remove(dcc->tagconn);

	g_free_not_null(dcc->file);
	dcc->file = dcc_get_download_path(dcc->arg);

	/* if some plugin wants to change the file name/path here.. */
	signal_emit("dcc get receive", 1, dcc);

	if (stat(dcc->file, &statbuf) == 0 &&
	    dcc->get_type == DCC_GET_RENAME) {
		/* file exists, rename.. */
		fname = dcc_get_rename_file(dcc->file);
		g_free(dcc->file);
		dcc->file = fname;
	}

	if (dcc->get_type != DCC_GET_RESUME) {
		dcc->fhandle = open(dcc->file, O_WRONLY | O_TRUNC | O_CREAT, dcc_file_create_mode);
		if (dcc->fhandle == -1) {
			signal_emit("dcc error file create", 2, dcc, dcc->file);
			dcc_destroy(dcc);
			return;
		}
	}

	dcc->databufsize = settings_get_int("dcc_block_size");
        if (dcc->databufsize <= 0) dcc->databufsize = 2048;
	dcc->databuf = g_malloc(dcc->databufsize);

	dcc->starttime = time(NULL);
	dcc->tagread = g_input_add(dcc->handle, G_INPUT_READ,
				   (GInputFunction) sig_dccget_receive, dcc);
	signal_emit("dcc connected", 1, dcc);
}

void dcc_get_connect(DCC_REC *dcc)
{
	if (dcc->get_type == DCC_GET_DEFAULT) {
		dcc->get_type = settings_get_bool("dcc_autorename") ?
			DCC_GET_RENAME : DCC_GET_OVERWRITE;
	}


	dcc->handle = net_connect_ip(&dcc->addr, dcc->port,
				     source_host_ok ? source_host_ip : NULL);
	if (dcc->handle != NULL) {
		dcc->tagconn = g_input_add(dcc->handle,
					   G_INPUT_WRITE | G_INPUT_READ,
					   (GInputFunction) sig_dccget_connected, dcc);
	} else {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(dcc);
	}
}

#define get_params_match(params, pos) \
	((is_numeric(params[pos], '\0') || is_ipv6_address(params[pos])) && \
	is_numeric(params[(pos)+1], '\0') && atol(params[(pos)+1]) < 65536 && \
	is_numeric(params[(pos)+2], '\0'))

/* Return number of parameters in `params' that belong to file name.
   Normally it's paramcount-3, but I don't think anything forbids of
   adding some extension where there could be more parameters after
   file size.

   MIRC sends filenames with spaces quoted ("file name"), but I'd rather
   not trust that entirely either. At least some clients that don't really
   understand the problem with spaces in file names sends the file name
   without any quotes. */
int get_file_params_count(char **params, int paramcount)
{
	int pos, best;

	if (*params[0] == '"') {
		/* quoted file name? */
		for (pos = 0; pos < paramcount-3; pos++) {
			if (params[pos][strlen(params[pos])-1] == '"' &&
			    get_params_match(params, pos+1))
				return pos+1;
		}
	}

        best = paramcount-3;
	for (pos = paramcount-3; pos > 0; pos--) {
		if (get_params_match(params, pos))
                        best = pos;
	}

        return best;
}

/* CTCP: DCC SEND */
static void ctcp_msg_dcc_send(IRC_SERVER_REC *server, const char *data,
			      const char *nick, const char *addr,
			      const char *target, DCC_REC *chat)
{
	DCC_REC *dcc;
        IPADDR ip;
	char **params, *fname;
	int paramcount, fileparams;
	int port, len, quoted = FALSE;
        long size;

	/* SEND <file name> <address> <port> <size> [...] */
	params = g_strsplit(data, " ", -1);
	paramcount = strarray_length(params);

	if (paramcount < 4) {
		signal_emit("dcc error ctcp", 5, "SEND", data,
			    nick, addr, target);
		g_strfreev(params);
                return;
	}

	fileparams = get_file_params_count(params, paramcount);

	dcc_get_address(params[fileparams], &ip);
	port = atoi(params[fileparams+1]);
	size = atol(params[fileparams+2]);

	params[fileparams] = NULL;
        fname = g_strjoinv(" ", params);
	g_strfreev(params);

        len = strlen(fname);
	if (len > 1 && *fname == '"' && fname[len-1] == '"') {
		/* "file name" - MIRC sends filenames with spaces like this */
		fname[len-1] = '\0';
		g_memmove(fname, fname+1, len);
                quoted = TRUE;
	}

	dcc = dcc_find_request(DCC_TYPE_GET, nick, fname);
	if (dcc != NULL) {
		/* same DCC request offered again, remove the old one */
		dcc_destroy(dcc);
	}

	dcc = dcc_create(DCC_TYPE_GET, nick, fname, server, chat);
	dcc->target = g_strdup(target);
        memcpy(&dcc->addr, &ip, sizeof(ip));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;
	dcc->size = size;
        dcc->file_quoted = quoted;

	signal_emit("dcc request", 2, dcc, addr);

        g_free(fname);
}

/* handle receiving DCC - GET/RESUME. */
void cmd_dcc_receive(const char *data, DCC_GET_FUNC accept)
{
        DCC_REC *dcc;
	GSList *tmp, *next;
	char *nick, *fname;
	void *free_arg;
	int found;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &nick, &fname))
		return;

	if (*nick == '\0') {
		dcc = dcc_find_request_latest(DCC_TYPE_GET);
		if (dcc != NULL)
			accept(dcc);
		cmd_params_free(free_arg);
		return;
	}

	found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (dcc_is_waiting_get(dcc) &&
		    g_strcasecmp(dcc->nick, nick) == 0 &&
		    (*fname == '\0' || strcmp(dcc->arg, fname) == 0)) {
			found = TRUE;
			accept(dcc);
		}
	}

	if (!found)
		signal_emit("dcc error get not found", 1, nick);

	cmd_params_free(free_arg);
}

/* SYNTAX: DCC GET [<nick> [<file>]] */
static void cmd_dcc_get(const char *data)
{
        cmd_dcc_receive(data, dcc_get_connect);
}

static void read_settings(void)
{
	dcc_file_create_mode =
		octal2dec(settings_get_int("dcc_file_create_mode"));
}

void dcc_get_init(void)
{
	settings_add_bool("dcc", "dcc_autorename", FALSE);
	settings_add_str("dcc", "dcc_download_path", "~");
	settings_add_int("dcc", "dcc_file_create_mode", 644);

        read_settings();
	signal_add("ctcp msg dcc send", (SIGNAL_FUNC) ctcp_msg_dcc_send);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	command_bind("dcc get", NULL, (SIGNAL_FUNC) cmd_dcc_get);
}

void dcc_get_deinit(void)
{
	signal_remove("ctcp msg dcc send", (SIGNAL_FUNC) ctcp_msg_dcc_send);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	command_unbind("dcc get", (SIGNAL_FUNC) cmd_dcc_get);
}
