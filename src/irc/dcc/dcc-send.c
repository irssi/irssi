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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "network.h"
#include "net-sendbuffer.h"
#include "misc.h"
#include "settings.h"

#include "dcc-send.h"
#include "dcc-chat.h"

static SEND_DCC_REC *dcc_send_create(IRC_SERVER_REC *server,
				     CHAT_DCC_REC *chat,
				     const char *nick, const char *arg)
{
	SEND_DCC_REC *dcc;

	dcc = g_new0(SEND_DCC_REC, 1);
	dcc->orig_type = module_get_uniq_id_str("DCC", "GET");
	dcc->type = module_get_uniq_id_str("DCC", "SEND");
	dcc->fhandle = -1;

	dcc_init_rec(DCC(dcc), server, chat, nick, arg);
        return dcc;
}

static void sig_dcc_destroyed(SEND_DCC_REC *dcc)
{
	if (!IS_DCC_SEND(dcc)) return;

	if (dcc->fhandle != -1) close(dcc->fhandle);
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

	if (dcc->count_pos == 4)
		return;

	/* we need to get 4 bytes.. */
	ret = net_receive(dcc->handle, dcc->count_buf+dcc->count_pos,
			  4-dcc->count_pos);
	if (ret == -1) {
		dcc_close(DCC(dcc));
		return;
	}

	dcc->count_pos += ret;

	if (dcc->count_pos != 4)
		return;

	memcpy(&bytes, dcc->count_buf, 4);
	bytes = (guint32) ntohl(bytes);

	dcc->gotalldata = (unsigned long) bytes == dcc->transfd;
	dcc->count_pos = 0;

	if (dcc->waitforend && dcc->gotalldata) {
		/* file is sent */
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

	g_source_remove(dcc->tagconn);
	net_disconnect(dcc->handle);

	dcc->starttime = time(NULL);
	dcc->handle = handle;
	memcpy(&dcc->addr, &addr, sizeof(IPADDR));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;

	dcc->tagread = g_input_add(handle, G_INPUT_READ,
				   (GInputFunction) dcc_send_read_size, dcc);
	dcc->tagwrite = g_input_add(handle, G_INPUT_WRITE,
				    (GInputFunction) dcc_send_data, dcc);

	signal_emit("dcc connected", 1, dcc);
}

static char *dcc_send_get_file(const char *fname)
{
	char *str, *path;

	str = convert_home(fname);
	if (!g_path_is_absolute(str)) {
		/* full path not given to file, use dcc_upload_path */
		g_free(str);

		path = convert_home(settings_get_str("dcc_upload_path"));
		str = g_strconcat(path, G_DIR_SEPARATOR_S, fname, NULL);
		g_free(path);
	}

        return str;
}

/* SYNTAX: DCC SEND <nick> <file> */
static void cmd_dcc_send(const char *data, IRC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
	char *target, *fname, *str;
	void *free_arg;
	char host[MAX_IP_LEN];
	int hfile, port;
	long fsize;
        SEND_DCC_REC *dcc;
	CHAT_DCC_REC *chat;
	IPADDR own_ip;
        GIOChannel *handle;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &target, &fname))
		return;
	if (*target == '\0' || *fname == '\0')
		cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	/* if we're in dcc chat, send the request via it. */
	chat = item_get_dcc(item);

	if (chat != NULL && (chat->mirc_ctcp ||
			     g_strcasecmp(target, chat->nick) != 0))
		chat = NULL;

	if ((server == NULL || !server->connected) && chat == NULL)
		cmd_param_error(CMDERR_NOT_CONNECTED);

	if (dcc_find_request(DCC_SEND_TYPE, target, fname)) {
		signal_emit("dcc error send exists", 2, target, fname);
		cmd_params_free(free_arg);
		return;
	}

        str = dcc_send_get_file(fname);
	hfile = open(str, O_RDONLY);
	g_free(str);

	if (hfile == -1) {
		signal_emit("dcc error file not found", 2, target, fname);
		cmd_params_free(free_arg);
		return;
	}
	fsize = lseek(hfile, 0, SEEK_END);
	lseek(hfile, 0, SEEK_SET);

        /* start listening */
	handle = dcc_listen(chat != NULL ? chat->handle :
			    net_sendbuffer_handle(server->handle),
			    &own_ip, &port);
	if (handle == NULL) {
		close(hfile);
		cmd_param_error(CMDERR_ERRNO);
	}

	fname = g_basename(fname);

	dcc = dcc_send_create(server, chat, target, fname);
        dcc->handle = handle;
	dcc->port = port;
	dcc->size = fsize;
	dcc->fhandle = hfile;
        dcc->file_quoted = strchr(fname, ' ') != NULL;
	dcc->tagconn = g_input_add(handle, G_INPUT_READ,
				   (GInputFunction) dcc_send_connected, dcc);

	/* send DCC request */
	dcc_ip2str(&own_ip, host);
	str = g_strdup_printf(dcc->file_quoted ?
			      "DCC SEND \"%s\" %s %d %lu" :
			      "DCC SEND %s %s %d %lu",
			      fname, host, port, fsize);
	dcc_ctcp_message(server, target, chat, FALSE, str);
	g_free(str);

	cmd_params_free(free_arg);
}

void dcc_send_init(void)
{
        dcc_register_type("SEND");
	settings_add_str("dcc", "dcc_upload_path", "~");

	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	command_bind("dcc send", NULL, (SIGNAL_FUNC) cmd_dcc_send);
}

void dcc_send_deinit(void)
{
        dcc_unregister_type("SEND");
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	command_unbind("dcc send", (SIGNAL_FUNC) cmd_dcc_send);
}
