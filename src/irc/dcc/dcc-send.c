/*
 dcc-send.c : irssi

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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/irc/core/irc-servers.h>

#include <irssi/src/irc/dcc/dcc-send.h>
#include <irssi/src/irc/dcc/dcc-chat.h>
#include <irssi/src/irc/dcc/dcc-queue.h>

#include <glob.h>

#ifndef GLOB_TILDE
#  define GLOB_TILDE 0 /* unsupported */
#endif

static int dcc_send_one_file(int queue, const char *target, const char *fname,
			     IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
			     int passive);

static void dcc_queue_send_next(int queue)
{
	IRC_SERVER_REC *server;
        DCC_QUEUE_REC *qrec;
	int send_started = FALSE;

	while ((qrec = dcc_queue_get_next(queue)) != NULL && !send_started) {
		server = qrec->servertag == NULL ? NULL :
			IRC_SERVER(server_find_tag(qrec->servertag));

		if (server == NULL && qrec->chat == NULL) {
			/* no way to send this request */
			signal_emit("dcc error send no route", 2,
				    qrec->nick, qrec->file);
		} else {
			send_started = dcc_send_one_file(queue, qrec->nick,
							 qrec->file, server,
							 qrec->chat,
							 qrec->passive);
		}
                dcc_queue_remove_head(queue);
	}

	if (!send_started) {
		/* no files in queue anymore, remove it */
		dcc_queue_free(queue);
	}
}

static char *dcc_send_get_file(const char *fname)
{
	char *str, *path;

	str = convert_home(fname);
	if (!g_path_is_absolute(str)) {
		/* full path not given to file, use dcc_upload_path */
		g_free(str);

		path = convert_home(settings_get_str("dcc_upload_path"));
		str = *path == '\0' ? g_strdup(fname) :
			g_strconcat(path, G_DIR_SEPARATOR_S, fname, NULL);
		g_free(path);
	}

        return str;
}

static void dcc_send_add(const char *servertag, CHAT_DCC_REC *chat,
			 const char *nick, char *fileargs, int add_mode,
			 int passive)
{
	struct stat st;
	glob_t globbuf;
	char *fname;
	int i, ret, files, flags, queue, start_new_transfer;

	memset(&globbuf, 0, sizeof(globbuf));
        flags = GLOB_NOCHECK | GLOB_TILDE;

	/* this loop parses all <file> parameters and adds them to glubbuf */
	for (;;) {
		fname = cmd_get_quoted_param(&fileargs);
		if (*fname == '\0')
			break;

		if (glob(fname, flags, 0, &globbuf) < 0)
			break;

		/* this flag must not be set before first call to glob!
		   (man glob) */
		flags |= GLOB_APPEND;
	}

	files = 0; queue = -1; start_new_transfer = 0;

	/* add all globbed files to a proper queue */
	for (i = 0; i < globbuf.gl_pathc; i++) {
		char *fname = dcc_send_get_file(globbuf.gl_pathv[i]);

		ret = stat(fname, &st);
		if (ret == 0 && S_ISDIR(st.st_mode)) {
			/* we don't want directories */
			errno = EISDIR;
			ret = -1;
		}

		if (ret < 0) {
			signal_emit("dcc error file open", 3,
				    nick, fname, errno);
			g_free(fname);
			continue;
		}

		if (queue < 0) {
			/* in append and prepend mode try to find an
			   old queue. if an old queue is not found
			   create a new queue. if not in append or
			   prepend mode, create a new queue */
			if (add_mode != DCC_QUEUE_NORMAL)
				queue = dcc_queue_old(nick, servertag);
			start_new_transfer = 0;
			if (queue < 0) {
				queue = dcc_queue_new();
				start_new_transfer = 1;
			}
		}

		dcc_queue_add(queue, add_mode, nick,
			      fname, servertag, chat, passive);
		files++;
		g_free(fname);
	}

	if (files > 0 && start_new_transfer)
		dcc_queue_send_next(queue);

	globfree(&globbuf);
}

/* DCC SEND [-append | -prepend | -flush | -rmtail | -rmhead | -passive]
            <nick> <file> [<file> ...] */
static void cmd_dcc_send(const char *data, IRC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
	const char *servertag;
	char *nick, *fileargs;
	void *free_arg;
	CHAT_DCC_REC *chat;
	GHashTable *optlist;
	int queue, mode, passive;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST | PARAM_FLAG_STRIP_TRAILING_WS, 
			    "dcc send", &optlist, &nick, &fileargs))
		return;

	chat = item_get_dcc(item);
	if (chat != NULL &&
	    (chat->mirc_ctcp || g_ascii_strcasecmp(nick, chat->nick) != 0))
		chat = NULL;

	if (IS_IRC_SERVER(server) && server->connected)
		servertag = server->tag;
	else if (chat != NULL)
		servertag = chat->servertag;
	else
		servertag = NULL;

	if (servertag == NULL && chat == NULL)
		cmd_param_error(CMDERR_NOT_CONNECTED);

	passive = g_hash_table_lookup(optlist, "passive") != NULL;

	if (g_hash_table_lookup(optlist, "rmhead") != NULL) {
		queue = dcc_queue_old(nick, servertag);
		if (queue != -1)
			dcc_queue_remove_head(queue);
	} else if (g_hash_table_lookup(optlist, "rmtail") != NULL) {
		queue = dcc_queue_old(nick, servertag);
		if (queue != -1)
			dcc_queue_remove_tail(queue);
	} else if (g_hash_table_lookup(optlist, "flush") != NULL) {
		queue = dcc_queue_old(nick, servertag);
		if (queue != -1)
			dcc_queue_free(queue);
	} else {
		if (g_hash_table_lookup(optlist, "append") != NULL)
			mode = DCC_QUEUE_APPEND;
		else if (g_hash_table_lookup(optlist, "prepend") != NULL)
			mode = DCC_QUEUE_PREPEND;
		else
			mode = DCC_QUEUE_NORMAL;

		if (*fileargs == '\0')
			cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

		dcc_send_add(servertag, chat, nick, fileargs, mode, passive);
	}

	cmd_params_free(free_arg);
}

static SEND_DCC_REC *dcc_send_create(IRC_SERVER_REC *server,
				     CHAT_DCC_REC *chat,
				     const char *nick, const char *arg)
{
	SEND_DCC_REC *dcc;

	dcc = g_new0(SEND_DCC_REC, 1);
	dcc->orig_type = module_get_uniq_id_str("DCC", "GET");
	dcc->type = module_get_uniq_id_str("DCC", "SEND");
	dcc->fhandle = -1;
	dcc->queue = -1;

	dcc_init_rec(DCC(dcc), server, chat, nick, arg);
	if (dcc->module_data == NULL) {
		/* failed to successfully init; TODO: change API */
		g_free(dcc);
		return NULL;
	}

        return dcc;
}

static void sig_dcc_destroyed(SEND_DCC_REC *dcc)
{
	if (!IS_DCC_SEND(dcc)) return;

	if (dcc->fhandle != -1)
		close(dcc->fhandle);

	dcc_queue_send_next(dcc->queue);
}

/* input function: DCC SEND - we're ready to send more data */
static void dcc_send_data(SEND_DCC_REC *dcc)
{
        char buffer[512];
	int ret;

	ret = read(dcc->fhandle, buffer, sizeof(buffer));
	if (ret <= 0) {
		/* no need to call this function anymore..
		   in fact it just eats all the cpu.. */
		dcc->waitforend = TRUE;
		g_source_remove(dcc->tagwrite);
		dcc->tagwrite = -1;
		return;
	}

	ret = net_transmit(dcc->handle, buffer, ret);
	if (ret > 0) dcc->transfd += ret;
	dcc->gotalldata = FALSE;

	lseek(dcc->fhandle, dcc->transfd, SEEK_SET);

	signal_emit("dcc transfer update", 1, dcc);
}

/* input function: DCC SEND - received some data */
static void dcc_send_read_size(SEND_DCC_REC *dcc)
{
	guint32 bytes;
	int ret;

	ret = net_receive(dcc->handle, dcc->count_buf+dcc->count_pos,
			  4-dcc->count_pos);
	if (ret == -1) {
		dcc_close(DCC(dcc));
		return;
	}

	dcc->count_pos += ret;

	if (dcc->count_pos != 4)
		return;

	memcpy(&bytes, dcc->count_buf, sizeof(bytes));
	bytes = ntohl(bytes);
	dcc->count_pos = 0;

	if (dcc->waitforend && bytes == (dcc->transfd & 0xffffffff)) {
		/* file is sent */
		dcc->gotalldata = TRUE;
		dcc_close(DCC(dcc));
	}
}

/* input function: DCC SEND - someone tried to connect to our socket */
static void dcc_send_connected(SEND_DCC_REC *dcc)
{
        GIOChannel *handle;
	IPADDR addr;
	int port;

	/* accept connection */
	handle = net_accept(dcc->handle, &addr, &port);
	if (handle == NULL)
		return;

	/* TODO: some kind of paranoia check would be nice. it would check
	   that the host of the nick who we sent the request matches the
	   address who connected us. */

	net_disconnect(dcc->handle);
	g_source_remove(dcc->tagconn);
        dcc->tagconn = -1;

	dcc->starttime = time(NULL);
	dcc->handle = handle;
	memcpy(&dcc->addr, &addr, sizeof(IPADDR));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;

	dcc->tagread = i_input_add(handle, I_INPUT_READ, (GInputFunction) dcc_send_read_size, dcc);
	dcc->tagwrite = i_input_add(handle, I_INPUT_WRITE, (GInputFunction) dcc_send_data, dcc);

	signal_emit("dcc connected", 1, dcc);
}

/* input function: DCC SEND - connect to the receiver (passive protocol) */
static void dcc_send_connect(SEND_DCC_REC *dcc)
{
	dcc->handle = dcc_connect_ip(&dcc->addr, dcc->port);

	if (dcc->handle != NULL) {
		dcc->starttime = time(NULL);

		dcc->tagread = i_input_add(dcc->handle, I_INPUT_READ,
		                           (GInputFunction) dcc_send_read_size, dcc);
		dcc->tagwrite =
		    i_input_add(dcc->handle, I_INPUT_WRITE, (GInputFunction) dcc_send_data, dcc);
		signal_emit("dcc connected", 1, dcc);
	} else {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(DCC(dcc));
	}
}

static int dcc_send_one_file(int queue, const char *target, const char *fname,
			     IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
			     int passive)
{
	struct stat st;
	char *str;
	char host[MAX_IP_LEN];
	int hfile, port = 0;
        SEND_DCC_REC *dcc;
	IPADDR own_ip;
	GIOChannel *handle;

	if (dcc_find_request(DCC_SEND_TYPE, target, fname)) {
		signal_emit("dcc error send exists", 2, target, fname);
		return FALSE;
	}

	str = dcc_send_get_file(fname);
	hfile = open(str, O_RDONLY);
	g_free(str);

	if (hfile == -1) {
		signal_emit("dcc error file open", 3, target, fname,
			    GINT_TO_POINTER(errno));
		return FALSE;
	}

	if (fstat(hfile, &st) < 0) {
		g_warning("fstat() failed: %s", strerror(errno));
		close(hfile);
		return FALSE;
	}

	/* start listening (only if passive == FALSE )*/

	if (passive == FALSE) {
		handle = dcc_listen(chat != NULL ? chat->handle :
				    net_sendbuffer_handle(server->handle),
				    &own_ip, &port);
		if (handle == NULL) {
			close(hfile);
			g_warning("dcc_listen() failed: %s", strerror(errno));
			return FALSE;
		}
	} else {
		handle = NULL;
	}

	str = g_path_get_basename(fname);

	/* Replace all the spaces with underscore so that lesser
	   intelligent clients can communicate.. */
	if (settings_get_bool("dcc_send_replace_space_with_underscore"))
		g_strdelimit(str, " ", '_');

	dcc = dcc_send_create(server, chat, target, str);
	g_free(str);
	if (dcc == NULL) {
		g_warn_if_reached();
		close(hfile);
		return FALSE;
	}

	dcc->handle = handle;
	dcc->port = port;
	dcc->size = st.st_size;
	dcc->fhandle = hfile;
	dcc->queue = queue;
        dcc->file_quoted = strchr(fname, ' ') != NULL;
	if (!passive) {
		dcc->tagconn =
		    i_input_add(handle, I_INPUT_READ, (GInputFunction) dcc_send_connected, dcc);
	}

	/* Generate an ID for this send if using passive protocol */
	if (passive) {
		dcc->pasv_id = rand() % 64;
	}

	/* send DCC request */
	signal_emit("dcc request send", 1, dcc);


	dcc_ip2str(&own_ip, host);
	if (passive == FALSE) {
		str = g_strdup_printf(dcc->file_quoted ?
				      "DCC SEND \"%s\" %s %d %"PRIuUOFF_T :
				      "DCC SEND %s %s %d %"PRIuUOFF_T,
				      dcc->arg, host, port, dcc->size);
	} else {
		str = g_strdup_printf(dcc->file_quoted ?
				      "DCC SEND \"%s\" 16843009 0 %"PRIuUOFF_T" %d" :
				      "DCC SEND %s 16843009 0 %"PRIuUOFF_T" %d",
				      dcc->arg, dcc->size, dcc->pasv_id);
	}
	dcc_ctcp_message(server, target, chat, FALSE, str);

	g_free(str);
	return TRUE;
}

void dcc_send_init(void)
{
        dcc_register_type("SEND");
	settings_add_str("dcc", "dcc_upload_path", "~");
	settings_add_bool("dcc", "dcc_send_replace_space_with_underscore", FALSE);
	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_add("dcc reply send pasv", (SIGNAL_FUNC) dcc_send_connect);
	command_bind("dcc send", NULL, (SIGNAL_FUNC) cmd_dcc_send);
	command_set_options("dcc send", "append flush prepend rmhead rmtail passive");

	dcc_queue_init();
}

void dcc_send_deinit(void)
{
	dcc_queue_deinit();

        dcc_unregister_type("SEND");
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_remove("dcc reply send pasv", (SIGNAL_FUNC) dcc_send_connect);
	command_unbind("dcc send", (SIGNAL_FUNC) cmd_dcc_send);
}
