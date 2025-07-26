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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/irc/core/irc-servers.h>

#include <irssi/src/irc/dcc/dcc-get.h>
#include <irssi/src/irc/dcc/dcc-send.h>

static char *dcc_get_recv_buffer;

GET_DCC_REC *dcc_get_create(IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
				   const char *nick, const char *arg)
{
	GET_DCC_REC *dcc;

	dcc = g_new0(GET_DCC_REC, 1);
	dcc->orig_type = module_get_uniq_id_str("DCC", "SEND");
	dcc->type = module_get_uniq_id_str("DCC", "GET");
	dcc->fhandle = -1;

	dcc_init_rec(DCC(dcc), server, chat, nick, arg);
	if (dcc->module_data == NULL) {
		/* failed to successfully init; TODO: change API */
		g_free(dcc);
		return NULL;
	}

        return dcc;
}

static void sig_dcc_destroyed(GET_DCC_REC *dcc)
{
	if (!IS_DCC_GET(dcc)) return;

	g_free_not_null(dcc->file);
	if (dcc->fhandle != -1) close(dcc->fhandle);
}

char *dcc_get_download_path(const char *fname)
{
	char *str, *downpath;
	char *base;

	base = g_path_get_basename(fname);
	downpath = convert_home(settings_get_str("dcc_download_path"));
	str = g_strconcat(downpath, G_DIR_SEPARATOR_S, base, NULL);
	g_free(downpath);
	g_free(base);

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
		g_string_printf(newname, "%s.%d", fname, num);
		num++;
	} while (stat(newname->str, &statbuf) == 0);

	ret = g_string_free_and_steal(newname);
	return ret;
}

static void sig_dccget_send(GET_DCC_REC *dcc);

void dcc_get_send_received(GET_DCC_REC *dcc)
{
	guint32 recd;

	recd = (guint32) htonl(dcc->transfd & 0xffffffff);
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
		dcc->tagwrite =
		    i_input_add(dcc->handle, I_INPUT_WRITE, (GInputFunction) sig_dccget_send, dcc);
	}
}

/* input function: DCC GET is free to send data */
static void sig_dccget_send(GET_DCC_REC *dcc)
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
	if (recd != (guint32) htonl(dcc->transfd & 0xffffffff))
                dcc_get_send_received(dcc);
}

#define DCC_GET_RECV_BUFFER_SIZE 32768

/* input function: DCC GET received data */
static void sig_dccget_receive(GET_DCC_REC *dcc)
{
	int ret;

	if (dcc_get_recv_buffer == NULL) {
		dcc_get_recv_buffer = g_malloc(DCC_GET_RECV_BUFFER_SIZE);
	}

	for (;;) {
		ret = net_receive(dcc->handle, dcc_get_recv_buffer,
				  DCC_GET_RECV_BUFFER_SIZE);
		if (ret == 0) break;

		if (ret < 0) {
			/* socket closed - transmit complete,
			   or other side died.. */
			dcc_close(DCC(dcc));
			return;
		}

		if (write(dcc->fhandle, dcc_get_recv_buffer, ret) != ret) {
			/* most probably out of disk space */
			signal_emit("dcc error write", 2,
				    dcc, g_strerror(errno));
			dcc_close(DCC(dcc));
                        return;
		}
		dcc->transfd += ret;
		break;
	}

	/* send number of total bytes received */
	if (dcc->count_pos <= 0)
		dcc_get_send_received(dcc);

	signal_emit("dcc transfer update", 1, dcc);
}

/* callback: net_connect() finished for DCC GET */
void sig_dccget_connected(GET_DCC_REC *dcc)
{
	struct stat statbuf;
	char *fname, *tempfname, *str;
        int ret, ret_errno, temphandle, old_umask;

	if (!dcc->from_dccserver) {
		if (net_geterror(dcc->handle) != 0) {
			/* error connecting */
			signal_emit("dcc error connect", 1, dcc);
			dcc_destroy(DCC(dcc));
			return;
		}

		g_source_remove(dcc->tagconn);
		dcc->tagconn = -1;
	}

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
		int dcc_file_create_mode = octal2dec(settings_get_int("dcc_file_create_mode"));

		/* we want to overwrite the file, remove it here.
		   if it gets created after this, we'll fail. */
		unlink(dcc->file);

		/* just to make sure we won't run into race conditions
		   if download_path is in some global temp directory */
		tempfname = g_strconcat(dcc->file, ".XXXXXX", NULL);

                old_umask = umask(0077);
		temphandle = mkstemp(tempfname);
		umask(old_umask);

		if (temphandle == -1)
			ret = -1;
		else {
			if (fchmod(temphandle, dcc_file_create_mode) != 0)
				g_warning("fchmod(3) failed: %s", strerror(errno));
			/* proceed even if chmod fails */
			ret = 0;
		}

		close(temphandle);

		if (ret != -1) {
			ret = link(tempfname, dcc->file);

			if (ret == -1 &&
			    /* Linux */
			    (errno == EPERM ||
			     /* FUSE */
			     errno == ENOSYS || errno == EACCES ||
			     /* BSD */
			     errno == EOPNOTSUPP)) {
				/* hard links aren't supported - some people
				   want to download stuff to FAT/NTFS/etc
				   partitions, so fallback to rename() */
				ret = rename(tempfname, dcc->file);
			}
		}

		/* if ret = 0, we're the file owner now */
		dcc->fhandle = ret == -1 ? -1 :
			open(dcc->file, O_WRONLY | O_TRUNC);

		/* close/remove the temp file */
		ret_errno = errno;
		unlink(tempfname);
		g_free(tempfname);

		if (dcc->fhandle == -1) {
			signal_emit("dcc error file create", 3,
				    dcc, dcc->file, g_strerror(ret_errno));
			dcc_destroy(DCC(dcc));
			return;
		}
	}

	dcc->starttime = time(NULL);
	if (dcc->size == 0) {
		dcc_close(DCC(dcc));
		return;
	}
	dcc->tagread =
	    i_input_add(dcc->handle, I_INPUT_READ, (GInputFunction) sig_dccget_receive, dcc);
	signal_emit("dcc connected", 1, dcc);

	if (dcc->from_dccserver) {
		str = g_strdup_printf("121 %s %d\n",
				      dcc->server ? dcc->server->nick : "??", 0);
		net_transmit(dcc->handle, str, strlen(str));
	}
}

void dcc_get_connect(GET_DCC_REC *dcc)
{
	if (dcc->get_type == DCC_GET_DEFAULT) {
		dcc->get_type = settings_get_bool("dcc_autorename") ?
			DCC_GET_RENAME : DCC_GET_OVERWRITE;
	}

	if (dcc->from_dccserver) {
		sig_dccget_connected(dcc);
		return;
	}

	dcc->handle = dcc_connect_ip(&dcc->addr, dcc->port);

	if (dcc->handle != NULL) {
		dcc->tagconn = i_input_add(dcc->handle, I_INPUT_WRITE | I_INPUT_READ,
		                           (GInputFunction) sig_dccget_connected, dcc);
	} else {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(DCC(dcc));
	}
}

static void dcc_get_listen(GET_DCC_REC *dcc)
{
	GIOChannel *handle;
	IPADDR addr;
	int port;

	/* accept connection */
	handle = net_accept(dcc->handle, &addr, &port);
	if (handle == NULL)
		return;

	net_disconnect(dcc->handle);
	g_source_remove(dcc->tagconn);
	dcc->tagconn = -1;

	dcc->starttime = time(NULL);
	dcc->handle = handle;
	memcpy(&dcc->addr, &addr, sizeof(IPADDR));
	net_ip2host(&dcc->addr, dcc->addrstr);
	dcc->port = port;

	dcc->tagconn = i_input_add(handle, I_INPUT_READ | I_INPUT_WRITE,
	                           (GInputFunction) sig_dccget_connected, dcc);
}

void dcc_get_passive(GET_DCC_REC *dcc)
{
	GIOChannel *handle;
	IPADDR own_ip;
	int port;
	char host[MAX_IP_LEN];

	handle = dcc_listen(net_sendbuffer_handle(dcc->server->handle),
			    &own_ip, &port);
	if (handle == NULL)
		cmd_return_error(CMDERR_ERRNO);

	dcc->handle = handle;
	dcc->tagconn = i_input_add(dcc->handle, I_INPUT_READ, (GInputFunction) dcc_get_listen, dcc);

	/* Let's send the reply to the other client! */
	dcc_ip2str(&own_ip, host);
	irc_send_cmdv(dcc->server,
		      "PRIVMSG %s :\001DCC SEND %s %s %d %"PRIuUOFF_T" %d\001",
		      dcc->nick, dcc->arg, host, port, dcc->size, dcc->pasv_id);
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
			if (strlen(params[pos]) == 0)
				continue;
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

char *get_file_name(char **params, int fileparams)
{
	GString *out = g_string_new(params[0]);
	char *ret;
	int pos;

	for (pos = 1; pos < fileparams; pos++) {
		out = g_string_append(out, " ");
		out = g_string_append(out, params[pos]);
	}

	ret = g_string_free_and_steal(out);
	return ret;
}

/* CTCP: DCC SEND */
static void ctcp_msg_dcc_send(IRC_SERVER_REC *server, const char *data,
			      const char *nick, const char *addr,
			      const char *target, CHAT_DCC_REC *chat)
{
	GET_DCC_REC *dcc;
	SEND_DCC_REC *temp_dcc;
	IPADDR ip;
	char *address, **params, *fname;
	int paramcount, fileparams;
	int port, len, quoted = FALSE;
        uoff_t size;
	int p_id = -1;
	int passive = FALSE;

	if (addr == NULL)
		addr = "";
	if (nick == NULL)
		nick = "";

	/* SEND <file name> <address> <port> <size> [...] */
	/* SEND <file name> <address> 0 <size> <id> (DCC SEND passive protocol) */
	params = g_strsplit(data, " ", -1);
	paramcount = g_strv_length(params);

	if (paramcount < 4) {
		signal_emit("dcc error ctcp", 5, "SEND", data,
			    nick, addr, target);
		g_strfreev(params);
                return;
	}

	fileparams = get_file_params_count(params, paramcount);

	address = g_strdup(params[fileparams]);
	dcc_str2ip(address, &ip);
	port = atoi(params[fileparams+1]);
	size = str_to_uofft(params[fileparams+2]);

	/* If this DCC uses passive protocol then store the id for later use. */
	if (paramcount == fileparams + 4) {
		p_id = atoi(params[fileparams+3]);
		passive = TRUE;
	}

	fname = get_file_name(params, fileparams);
	g_strfreev(params);

        len = strlen(fname);
	if (len > 1 && *fname == '"' && fname[len-1] == '"') {
		/* "file name" - MIRC sends filenames with spaces like this */
		fname[len-1] = '\0';
		memmove(fname, fname+1, len);
		quoted = TRUE;
	}

	if (passive && port != 0) {
		/* This is NOT a DCC SEND request! This is a reply to our
		   passive request. We MUST check the IDs and then connect to
		   the remote host. */

		temp_dcc = DCC_SEND(dcc_find_request(DCC_SEND_TYPE, nick, fname));
		if (temp_dcc != NULL && p_id == temp_dcc->pasv_id) {
			temp_dcc->target = g_strdup(target);
			temp_dcc->port = port;
			temp_dcc->size = size;
			temp_dcc->file_quoted = quoted;

			memcpy(&temp_dcc->addr, &ip, sizeof(IPADDR));
			if (temp_dcc->addr.family == AF_INET)
				net_ip2host(&temp_dcc->addr, temp_dcc->addrstr);
			else {
				/* with IPv6, show it to us as it was sent */
				g_strlcpy(temp_dcc->addrstr, address,
					  sizeof(temp_dcc->addrstr));
			}

			/* This new signal is added to let us invoke
			   dcc_send_connect() which is found in dcc-send.c */
			signal_emit("dcc reply send pasv", 1, temp_dcc);
			g_free(address);
			g_free(fname);
			return;
		} else if (temp_dcc != NULL && p_id != temp_dcc->pasv_id) {
			/* IDs don't match... remove the old DCC SEND and
			   return */
			dcc_destroy(DCC(temp_dcc));
			g_free(address);
			g_free(fname);
			return;
		}
	}

	dcc = DCC_GET(dcc_find_request(DCC_GET_TYPE, nick, fname));
	if (dcc != NULL)
		dcc_destroy(DCC(dcc)); /* remove the old DCC */

	dcc = dcc_get_create(server, chat, nick, fname);
	if (dcc == NULL) {
		g_free(address);
		g_free(fname);
		g_warn_if_reached();
		return;
	}
	dcc->target = g_strdup(target);

	if (passive && port == 0)
		dcc->pasv_id = p_id; /* Assign the ID to the DCC */

	memcpy(&dcc->addr, &ip, sizeof(ip));
	if (dcc->addr.family == AF_INET)
		net_ip2host(&dcc->addr, dcc->addrstr);
	else {
		/* with IPv6, show it to us as it was sent */
		g_strlcpy(dcc->addrstr, address, sizeof(dcc->addrstr));
	}
	dcc->port = port;
	dcc->size = size;
	dcc->file_quoted = quoted;

	signal_emit("dcc request", 2, dcc, addr);

	g_free(address);
	g_free(fname);
}

/* handle receiving DCC - GET/RESUME. */
void cmd_dcc_receive(const char *data, DCC_GET_FUNC accept_func,
		     DCC_GET_FUNC pasv_accept_func)
{
	GET_DCC_REC *dcc;
	GSList *tmp, *next;
	char *nick, *arg, *fname;
	void *free_arg;
	int found;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST |
			    PARAM_FLAG_STRIP_TRAILING_WS, &nick, &arg))
		return;

	if (*nick == '\0') {
		dcc = DCC_GET(dcc_find_request_latest(DCC_GET_TYPE));
		if (dcc != NULL) {
			if (!dcc_is_passive(dcc))
				accept_func(dcc);
			else
				pasv_accept_func(dcc);
		}
		cmd_params_free(free_arg);
		return;
	}

	fname = cmd_get_quoted_param(&arg);

	found = FALSE;
	for (tmp = dcc_conns; tmp != NULL; tmp = next) {
		GET_DCC_REC *dcc = tmp->data;

		next = tmp->next;
		if (IS_DCC_GET(dcc) && g_ascii_strcasecmp(dcc->nick, nick) == 0 &&
		    (dcc_is_waiting_user(dcc) || dcc->from_dccserver) &&
		    (*fname == '\0' || g_strcmp0(dcc->arg, fname) == 0)) {
			found = TRUE;
			if (!dcc_is_passive(dcc))
				accept_func(dcc);
			else
				pasv_accept_func(dcc);
		}
	}

	if (!found)
		signal_emit("dcc error get not found", 1, nick);

	cmd_params_free(free_arg);
}

/* SYNTAX: DCC GET [<nick> [<file>]] */
static void cmd_dcc_get(const char *data)
{
	cmd_dcc_receive(data, dcc_get_connect, dcc_get_passive);
}

void dcc_get_init(void)
{
        dcc_register_type("GET");
	settings_add_bool("dcc", "dcc_autorename", FALSE);
	settings_add_str("dcc", "dcc_download_path", "~");
	settings_add_int("dcc", "dcc_file_create_mode", 644);

	signal_add("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_add("ctcp msg dcc send", (SIGNAL_FUNC) ctcp_msg_dcc_send);
	command_bind("dcc get", NULL, (SIGNAL_FUNC) cmd_dcc_get);
}

void dcc_get_deinit(void)
{
        dcc_unregister_type("GET");
	signal_remove("dcc destroyed", (SIGNAL_FUNC) sig_dcc_destroyed);
	signal_remove("ctcp msg dcc send", (SIGNAL_FUNC) ctcp_msg_dcc_send);
	command_unbind("dcc get", (SIGNAL_FUNC) cmd_dcc_get);
	g_free_and_null(dcc_get_recv_buffer);
}
