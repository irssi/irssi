/*
 dcc-files.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "net-sendbuffer.h"
#include "line-split.h"
#include "misc.h"
#include "settings.h"

#include "masks.h"
#include "irc.h"
#include "servers-setup.h"

#include "dcc.h"

static int dcc_file_create_mode;

static char *dcc_get_download_path(const char *fname)
{
	char *str, *downpath;

	downpath = convert_home(settings_get_str("dcc_download_path"));
	str = g_strconcat(downpath, G_DIR_SEPARATOR_S, g_basename(fname), NULL);
	g_free(downpath);

	return str;
}

static void sig_dccget_send(DCC_REC *dcc);

void dcc_get_send_received(DCC_REC *dcc)
{
	guint32 recd;

	recd = (guint32) htonl(dcc->transfd);
	memcpy(dcc->count_buf, &recd, 4);

	dcc->count_pos = net_transmit(dcc->handle, dcc->count_buf+dcc->count_pos, 4-dcc->count_pos);
	if (dcc->count_pos == 4) dcc->count_pos = 0;

	/* count_pos might be -1 here. if this happens, the
	   count_buf should be re-sent.. also, if it's 1, 2 or 3, the
	   last 1-3 bytes should be sent later. these happen probably
	   never, but I just want to do it right.. :) */
	if (dcc->tagwrite == -1) {
		dcc->tagwrite = g_input_add(dcc->handle, G_INPUT_WRITE,
					    (GInputFunction) sig_dccget_send, dcc);
	}
}

/* input function: DCC GET is free to send data */
static void sig_dccget_send(DCC_REC *dcc)
{
	guint32 recd;
	int ret;

	if (dcc->count_pos != 0) {
		ret = net_transmit(dcc->handle, dcc->count_buf+dcc->count_pos, 4-dcc->count_pos);
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

static char *get_rename_file(const char *fname)
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

	if (stat(dcc->file, &statbuf) == 0 && dcc->get_type == DCC_GET_RENAME) {
		/* file exists, rename.. */
		fname = get_rename_file(dcc->file);
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

static void dcc_get_connect(DCC_REC *dcc)
{
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

#define dcc_is_unget(dcc) \
        ((dcc)->type == DCC_TYPE_GET && (dcc)->handle == NULL)

/* SYNTAX: DCC GET <nick> [<file>] */
static void cmd_dcc_get(const char *data)
{
	DCC_REC *dcc;
	GSList *tmp, *next;
	char *nick, *fname;
	void *free_arg;
	int found;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &nick, &fname))
		return;
	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = NULL; found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		dcc = tmp->data;
		next = tmp->next;

		if (dcc_is_unget(dcc) && g_strcasecmp(dcc->nick, nick) == 0 &&
		    (*fname == '\0' || strcmp(dcc->arg, fname) == 0)) {
			found = TRUE;
			dcc_get_connect(dcc);
		}
	}

	if (!found)
		signal_emit("dcc error get not found", 1, nick);

	cmd_params_free(free_arg);
}

static void dcc_resume_send(DCC_REC *dcc, int port)
{
	char *str;

	g_return_if_fail(dcc != NULL);
	g_return_if_fail(dcc->type == DCC_TYPE_SEND);

	str = g_strdup_printf("DCC ACCEPT %s %d %lu",
			      dcc->arg, port, dcc->transfd);
	dcc_ctcp_message(dcc->nick, dcc->server, dcc->chat, FALSE, str);
	g_free(str);
}

#define is_resume_type(type) \
	(g_strcasecmp(type, "RESUME") == 0 || \
	g_strcasecmp(type, "ACCEPT") == 0)

#define is_resume_ok(type, dcc) \
	(g_strcasecmp(type, "RESUME") != 0 || \
	((dcc)->type == DCC_TYPE_SEND && (dcc)->transfd == 0))

#define is_accept_ok(type, dcc) \
	(g_strcasecmp(type, "ACCEPT") != 0 || \
	((dcc)->type == DCC_TYPE_GET && \
	(dcc)->get_type == DCC_GET_RESUME && (dcc)->handle == NULL))

static void dcc_ctcp_msg(const char *data, IRC_SERVER_REC *server,
			 const char *sender, const char *sendaddr,
			 const char *target, DCC_REC *chat)
{
	char *type, *arg, *portstr, *sizestr;
	void *free_arg;
	long size;
        int port;
	DCC_REC *dcc;

	g_return_if_fail(data != NULL);
	g_return_if_fail(sender != NULL);

	if (!cmd_get_params(data, &free_arg, 4 | PARAM_FLAG_NOQUOTES,
			    &type, &arg, &portstr, &sizestr))
		return;

	port = atoi(portstr);
	size = atol(sizestr);

	dcc = dcc_find_by_port(sender, port);
	if (dcc == NULL || !is_resume_type(type) ||
	    !is_resume_ok(type, dcc) || !is_accept_ok(type, dcc)) {
		cmd_params_free(free_arg);
		return;
	}

	if (lseek(dcc->fhandle, size, SEEK_SET) != size) {
		/* error, or trying to seek after end of file */
		signal_emit("dcc closed", 1, dcc);
		dcc_destroy(dcc);
	} else {
		dcc->transfd = dcc->skipped = size;

		if (dcc->type == DCC_TYPE_SEND)
			dcc_resume_send(dcc, port);
		else
			dcc_get_connect(dcc);
	}

	cmd_params_free(free_arg);
}

static void dcc_resume_rec(DCC_REC *dcc)
{
	char *str;

	g_return_if_fail(dcc != NULL);

	dcc->get_type = DCC_GET_RESUME;
	dcc->file = dcc_get_download_path(dcc->arg);

	dcc->fhandle = open(dcc->file, O_WRONLY, dcc_file_create_mode);
	if (dcc->fhandle == -1) {
		signal_emit("dcc error file not found", 2, dcc, dcc->file);
		dcc_destroy(dcc);
		return;
	}

	dcc->transfd = lseek(dcc->fhandle, 0, SEEK_END);
	if (dcc->transfd < 0) dcc->transfd = 0;
	dcc->skipped = dcc->transfd;

	str = g_strdup_printf("DCC RESUME %s %d %lu",
			      dcc->arg, dcc->port, dcc->transfd);
	dcc_ctcp_message(dcc->nick, dcc->server, dcc->chat, FALSE, str);
	g_free(str);
}

/* SYNTAX: DCC RESUME <nick> [<file>] */
static void cmd_dcc_resume(const char *data)
{
	DCC_REC *dcc;
	GSList *tmp;
	char *nick, *fname;
	void *free_arg;
	int found;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &nick, &fname))
		return;
	if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	dcc = NULL; found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		dcc = tmp->data;

		if (dcc_is_unget(dcc) && g_strcasecmp(dcc->nick, nick) == 0 &&
		    (*fname == '\0' || strcmp(dcc->arg, fname) == 0)) {
			dcc_resume_rec(dcc);
			found = TRUE;
		}
	}

	if (!found)
		signal_emit("dcc error get not found", 1, nick);

	cmd_params_free(free_arg);
}

/* input function: DCC SEND - we're ready to send more data */
static void dcc_send_data(DCC_REC *dcc)
{
	int ret;

	g_return_if_fail(dcc != NULL);

	if (!dcc->fastsend && !dcc->gotalldata) {
		/* haven't received everything we've send there yet.. */
		return;
	}

	ret = read(dcc->fhandle, dcc->databuf, dcc->databufsize);
	if (ret <= 0) {
		/* end of file .. or some error .. */
		if (dcc->fastsend) {
			/* no need to call this function anymore..
			   in fact it just eats all the cpu.. */
			dcc->waitforend = TRUE;
			g_source_remove(dcc->tagwrite);
			dcc->tagwrite = -1;
		} else {
			signal_emit("dcc closed", 1, dcc);
			dcc_destroy(dcc);
		}
		return;
	}

	ret = net_transmit(dcc->handle, dcc->databuf, ret);
	if (ret > 0) dcc->transfd += ret;
	dcc->gotalldata = FALSE;

	lseek(dcc->fhandle, dcc->transfd, SEEK_SET);

	signal_emit("dcc transfer update", 1, dcc);
}

/* input function: DCC SEND - received some data */
static void dcc_send_read_size(DCC_REC *dcc)
{
	guint32 bytes;
	int ret;

	g_return_if_fail(dcc != NULL);

	if (dcc->count_pos == 4)
		return;

	/* we need to get 4 bytes.. */
	ret = net_receive(dcc->handle, dcc->count_buf+dcc->count_pos, 4-dcc->count_pos);
	if (ret == -1) {
		signal_emit("dcc closed", 1, dcc);
		dcc_destroy(dcc);
		return;
	}

	dcc->count_pos += ret;

	if (dcc->count_pos != 4)
		return;

	memcpy(&bytes, dcc->count_buf, 4);
	bytes = (guint32) ntohl(bytes);

	dcc->gotalldata = (long) bytes == dcc->transfd;
	dcc->count_pos = 0;

	if (!dcc->fastsend) {
		/* send more data.. */
		dcc_send_data(dcc);
	}

	if (dcc->waitforend && dcc->gotalldata) {
		/* file is sent */
		signal_emit("dcc closed", 1, dcc);
		dcc_destroy(dcc);
	}
}

/* input function: DCC SEND - someone tried to connect to our socket */
static void dcc_send_init(DCC_REC *dcc)
{
        GIOChannel *handle;
	IPADDR addr;
	int port;

	g_return_if_fail(dcc != NULL);

	/* accept connection */
	handle = net_accept(dcc->handle, &addr, &port);
	if (handle == NULL)
		return;

	/* TODO: some kind of paranoia check would be nice. it would check
	   that the host of the nick who we sent the request matches the
	   address who connected us. */

	g_source_remove(dcc->tagconn);
	net_disconnect(dcc->handle);

	dcc->starttime = time(NULL);
	dcc->fastsend = settings_get_bool("dcc_fast_send");
	dcc->handle = handle;
	memcpy(&dcc->addr, &addr, sizeof(IPADDR));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;

	dcc->databufsize = settings_get_int("dcc_block_size");
        if (dcc->databufsize <= 0) dcc->databufsize = 2048;
	dcc->databuf = g_malloc(dcc->databufsize);

	dcc->tagread = g_input_add(handle, G_INPUT_READ,
				   (GInputFunction) dcc_send_read_size, dcc);
	dcc->tagwrite = !dcc->fastsend ? -1 :
		g_input_add(handle, G_INPUT_WRITE, (GInputFunction) dcc_send_data, dcc);

	signal_emit("dcc connected", 1, dcc);

	if (!dcc->fastsend) {
		/* send first block */
		dcc->gotalldata = TRUE;
		dcc_send_data(dcc);
	}
}

/* SYNTAX: DCC SEND <nick> <file> */
static void cmd_dcc_send(const char *data, IRC_SERVER_REC *server, void *item)
{
	char *target, *fname, *str, *ptr;
	void *free_arg;
	char host[MAX_IP_LEN];
	int hfile, port;
	long fsize;
	DCC_REC *dcc, *chat;
	IPADDR own_ip;
        GIOChannel *handle, *hlisten;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &fname))
		return;
	if (*target == '\0' || *fname == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	/* if we're in dcc chat, send the request via it. */
	chat = item_get_dcc(item);

	if (chat != NULL && (chat->mirc_ctcp || g_strcasecmp(target, chat->nick) != 0))
		chat = NULL;

	if ((server == NULL || !server->connected) && chat == NULL)
		cmd_param_error(CMDERR_NOT_CONNECTED);

	if (dcc_find_item(DCC_TYPE_SEND, target, fname)) {
		signal_emit("dcc error send exists", 2, target, fname);
		cmd_params_free(free_arg);
		return;
	}

	str = convert_home(fname);
	if (!g_path_is_absolute(str)) {
		char *path;

		g_free(str);
		path = convert_home(settings_get_str("dcc_upload_path"));
		str = g_strconcat(path, G_DIR_SEPARATOR_S, fname, NULL);
		g_free(path);
	}

	hfile = open(str, O_RDONLY);
	g_free(str);

	if (hfile == -1) {
		signal_emit("dcc error file not found", 2, target, fname);
		cmd_params_free(free_arg);
		return;
	}
	fsize = lseek(hfile, 0, SEEK_END);
	lseek(hfile, 0, SEEK_SET);

	/* get the IP address we use with IRC server */
	handle = chat != NULL ? chat->handle :
		net_sendbuffer_handle(server->handle);
	if (net_getsockname(handle, &own_ip, NULL) == -1) {
		close(hfile);
		cmd_param_error(CMDERR_ERRNO);
	}

	/* start listening */
	port = settings_get_int("dcc_port");
	hlisten = net_listen(&own_ip, &port);
	if (hlisten == NULL) {
		close(hfile);
		cmd_param_error(CMDERR_ERRNO);
	}

	/* skip path, change all spaces to _ */
	fname = g_strdup(g_basename(fname));
	for (ptr = fname; *ptr != '\0'; ptr++)
		if (*ptr == ' ') *ptr = '_';

	dcc = dcc_create(DCC_TYPE_SEND, hlisten, target, fname, server, chat);
	dcc->port = port;
	dcc->size = fsize;
	dcc->fhandle = hfile;
	dcc->tagconn = g_input_add(hlisten, G_INPUT_READ,
				   (GInputFunction) dcc_send_init, dcc);

	/* send DCC request */
	dcc_make_address(&own_ip, host);
	str = g_strdup_printf("DCC SEND %s %s %d %lu",
			      fname, host, port, fsize);
	dcc_ctcp_message(target, server, chat, FALSE, str);
	g_free(str);

	g_free(fname);
	cmd_params_free(free_arg);
}

static void read_settings(void)
{
	dcc_file_create_mode = octal2dec(settings_get_int("dcc_file_create_mode"));
}

void dcc_files_init(void)
{
	signal_add("ctcp msg dcc", (SIGNAL_FUNC) dcc_ctcp_msg);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("irssi init finished", (SIGNAL_FUNC) read_settings);
	command_bind("dcc send", NULL, (SIGNAL_FUNC) cmd_dcc_send);
	command_bind("dcc get", NULL, (SIGNAL_FUNC) cmd_dcc_get);
	command_bind("dcc resume", NULL, (SIGNAL_FUNC) cmd_dcc_resume);
}

void dcc_files_deinit(void)
{
	signal_remove("ctcp msg dcc", (SIGNAL_FUNC) dcc_ctcp_msg);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("irssi init finished", (SIGNAL_FUNC) read_settings);
	command_unbind("dcc send", (SIGNAL_FUNC) cmd_dcc_send);
	command_unbind("dcc get", (SIGNAL_FUNC) cmd_dcc_get);
	command_unbind("dcc resume", (SIGNAL_FUNC) cmd_dcc_resume);
}
