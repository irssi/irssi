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
#include "line-split.h"
#include "misc.h"
#include "settings.h"

#include "masks.h"
#include "irc.h"
#include "server-setup.h"

#include "dcc.h"

static gint dcc_file_create_mode;

static gchar *dcc_prepare_path(gchar *fname)
{
    gchar *str, *ptr, *downpath;

    /* strip all paths from file. */
    ptr = strrchr(fname, '/');
    if (ptr == NULL) ptr = fname; else ptr++;

    downpath = convert_home(settings_get_str("dcc_download_path"));
    str = g_strdup_printf("%s/%s", downpath, ptr);
    g_free(downpath);

    return str;
}

/* input function: DCC GET received data */
static void dcc_receive(DCC_REC *dcc)
{
    guint32 recd;
    gint len, ret;

    g_return_if_fail(dcc != NULL);

    for (;;)
    {
        len = net_receive(dcc->handle, dcc->databuf, dcc->databufsize);
        if (len == 0) break;
        if (len < 0)
        {
            /* socket closed - transmit complete (or other side died..) */
            signal_emit("dcc closed", 1, dcc);
            dcc_destroy(dcc);
            return;
        }

        write(dcc->fhandle, dcc->databuf, len);
        dcc->transfd += len;
    }

    /* send number of total bytes received - if for some reason we couldn't
       send the 4 characters last time, try to somehow fix it this time by
       sending missing amount of 0 characters.. */
    if (dcc->trans_bytes != 0)
    {
	recd = (guint32) htonl(0);
	dcc->trans_bytes += net_transmit(dcc->handle, ((gchar *) &recd)+dcc->trans_bytes, 4-dcc->trans_bytes);
	if (dcc->trans_bytes == 4) dcc->trans_bytes = 0;
    }

    if (dcc->trans_bytes == 0)
    {
	recd = (guint32) htonl(dcc->transfd);
	ret = net_transmit(dcc->handle, ((gchar *) &recd), 4);
	if (ret > 0 && ret < 4) dcc->trans_bytes = ret;
    }
    signal_emit("dcc transfer update", 1, dcc);
}

/* callback: net_connect() finished for DCC GET */
static void dcc_get_connect(DCC_REC *dcc)
{
    struct stat statbuf;

    g_return_if_fail(dcc != NULL);

    g_source_remove(dcc->tagread);
    if (net_geterror(dcc->handle) != 0)
    {
        /* error connecting */
        signal_emit("dcc error connect", 1, dcc);
        dcc_destroy(dcc);
        return;
    }
    dcc->file = dcc_prepare_path(dcc->arg);

    /* if some plugin wants to change the file name/path here.. */
    signal_emit("dcc get receive", 1, dcc);

    if (stat(dcc->file, &statbuf) == 0 &&
        (dcc->get_type == DCC_GET_RENAME || dcc->get_type == DCC_GET_DEFAULT))
    {
        /* file exists, rename.. */
        GString *newname;
        gint num;

        newname = g_string_new(NULL);
        for (num = 1; ; num++)
        {
            g_string_sprintf(newname, "%s.%d", dcc->file, num);
            if (stat(newname->str, &statbuf) != 0) break;
        }
        g_free(dcc->file);
        dcc->file = newname->str;
        g_string_free(newname, FALSE);
    }

    if (dcc->get_type != DCC_GET_RESUME)
    {
        dcc->fhandle = open(dcc->file, O_WRONLY | O_TRUNC | O_CREAT, dcc_file_create_mode);
        if (dcc->fhandle == -1)
        {
            signal_emit("dcc error file create", 2, dcc, dcc->file);
            dcc_destroy(dcc);
            return;
        }
    }

    dcc->databufsize = settings_get_int("dcc_block_size") > 0 ? settings_get_int("dcc_block_size") : 2048;
    dcc->databuf = g_malloc(dcc->databufsize);

    dcc->starttime = time(NULL);
    dcc->tagread = g_input_add(dcc->handle, G_INPUT_READ,
			       (GInputFunction) dcc_receive, dcc);
    signal_emit("dcc connected", 1, dcc);
}

/* command: DCC GET */
static void cmd_dcc_get(gchar *data)
{
    DCC_REC *dcc;
    GSList *tmp, *next;
    gchar *params, *nick, *fname;
    gboolean found;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &nick, &fname);
    if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

    dcc = NULL; found = FALSE;
    for (tmp = dcc_conns; tmp != NULL; tmp = next)
    {
	dcc = tmp->data;
	next = tmp->next;

        if (dcc->dcc_type == DCC_TYPE_GET && dcc->handle == -1 && g_strcasecmp(dcc->nick, nick) == 0 &&
            (*fname == '\0' || strcmp(dcc->arg, fname) == 0))
        {
	    /* found! */
	    found = TRUE;
	    dcc->handle = net_connect_ip(&dcc->addr, dcc->port,
					 source_host_ok ? source_host_ip : NULL);
	    if (dcc->handle != -1)
	    {
		dcc->tagread = g_input_add(dcc->handle, G_INPUT_WRITE,
					   (GInputFunction) dcc_get_connect, dcc);
	    }
	    else
	    {
		/* error connecting */
		signal_emit("dcc error connect", 1, dcc);
		dcc_destroy(dcc);
	    }
	}
    }

    if (!found)
        signal_emit("dcc error get not found", 1, nick);

    g_free(params);
}

/* resume setup: DCC SEND - we either said resume on get, or when we sent,
   someone chose resume */
static void dcc_resume_setup(DCC_REC *dcc, gint port)
{
    gchar *str;

    /* Check for DCC_SEND_RESUME */
    if (dcc->dcc_type == DCC_TYPE_SEND)
    {
        if (lseek(dcc->fhandle, dcc->transfd, SEEK_SET) == -1)
        {
            signal_emit("dcc closed", 1, dcc);
            dcc_destroy(dcc);
            return;
        }
        else
        {
            str = g_strdup_printf("DCC ACCEPT %s %d %lu",
                                  dcc->arg, port, dcc->transfd);
            dcc_ctcp_message(dcc->nick, dcc->server, dcc->chat, FALSE, str);
            g_free(str);
        }
    }

    /* Check for DCC_GET_RESUME */
    if (dcc->dcc_type == DCC_TYPE_GET && dcc->get_type == DCC_GET_RESUME)
    {
	dcc->handle = net_connect_ip(&dcc->addr, dcc->port,
				     source_host_ok ? source_host_ip : NULL);
	if (dcc->handle != -1)
	{
	    dcc->tagread = g_input_add(dcc->handle, G_INPUT_WRITE,
				       (GInputFunction) dcc_get_connect, dcc);
	}
	else
	{
	    /* error connecting */
	    signal_emit("dcc error connect", 1, dcc);
	    dcc_destroy(dcc);
	}
    }
}

static void dcc_ctcp_msg(gchar *data, IRC_SERVER_REC *server, gchar *sender, gchar *sendaddr, gchar *target, DCC_REC *chat)
{
    gchar *params, *type, *arg, *portstr, *sizestr;
    gulong size;
    gint port;
    DCC_REC *dcc;

    g_return_if_fail(data != NULL);
    g_return_if_fail(sender != NULL);

    params = cmd_get_params(data, 4, &type, &arg, &portstr, &sizestr);
    if (g_strcasecmp(type, "RESUME") == 0 || g_strcasecmp(type, "ACCEPT") == 0)
    {
        if (sscanf(portstr, "%d", &port) != 1) port = 0;
        if (sscanf(sizestr, "%lu", &size) != 1) size = 0;

	dcc = dcc_find_by_port(sender, port);
        if (dcc != NULL && (dcc->dcc_type == DCC_TYPE_GET || dcc->transfd == 0))
	{
	    dcc->transfd = size;
	    dcc->skipped = size;
	    dcc_resume_setup(dcc, port);
	}
    }

    g_free(params);
}

static void dcc_resume_rec(DCC_REC *dcc)
{
    gchar *str;

    dcc->file = dcc_prepare_path(dcc->arg);

    dcc->fhandle = open(dcc->file, O_WRONLY, dcc_file_create_mode);
    if (dcc->fhandle == -1)
    {
	signal_emit("dcc error file not found", 2, dcc, dcc->file);
	dcc_destroy(dcc);
    }
    else
    {
	dcc->transfd = lseek(dcc->fhandle, 0, SEEK_END);
	if (dcc->transfd < 0) dcc->transfd = 0;
	dcc->skipped = dcc->transfd;

	str = g_strdup_printf("DCC RESUME %s %d %lu",
			      dcc->arg, dcc->port, dcc->transfd);
	dcc_ctcp_message(dcc->nick, dcc->server, dcc->chat, FALSE, str);
	g_free(str);
    }
}

/* command: DCC RESUME */
static void cmd_dcc_resume(gchar *data)
{
    DCC_REC *dcc;
    GSList *tmp;
    gchar *params, *nick, *fname;
    gboolean found;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &nick, &fname);
    if (*nick == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

    dcc = NULL; found = FALSE;
    for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
    {
        dcc = tmp->data;

        if (dcc->dcc_type == DCC_TYPE_GET && dcc->handle == -1 && g_strcasecmp(dcc->nick, nick) == 0 &&
            (*fname == '\0' || strcmp(dcc->arg, fname) == 0))
        {
	    /* found! */
	    dcc->get_type = DCC_GET_RESUME;
	    dcc_resume_rec(dcc);
	    found = TRUE;
        }
    }

    if (!found)
        signal_emit("dcc error get not found", 1, nick);

    g_free(params);
}

/* input function: DCC SEND send more data */
static void dcc_send_data(DCC_REC *dcc)
{
    gint n;

    g_return_if_fail(dcc != NULL);

    if (!dcc->fastsend && !dcc->gotalldata)
    {
        /* haven't received everything we've send there yet.. */
        return;
    }

    n = read(dcc->fhandle, dcc->databuf, dcc->databufsize);
    if (n <= 0)
    {
        /* end of file .. or some error .. */
        if (dcc->fastsend)
        {
            /* no need to call this function anymore.. in fact it just eats
               all the cpu.. */
            dcc->waitforend = TRUE;
            g_source_remove(dcc->tagwrite);
            dcc->tagwrite = -1;
        }
        else
        {
            signal_emit("dcc closed", 1, dcc);
            dcc_destroy(dcc);
        }
        return;
    }

    dcc->transfd += net_transmit(dcc->handle, dcc->databuf, n);
    dcc->gotalldata = FALSE;

    lseek(dcc->fhandle, dcc->transfd, SEEK_SET);

    signal_emit("dcc transfer update", 1, dcc);
}

/* input function: DCC SEND received some data */
static void dcc_send_read_size(DCC_REC *dcc)
{
    guint32 bytes;
    gint ret;

    g_return_if_fail(dcc != NULL);

    if (dcc->read_pos == 4)
        return;

    /* we need to get 4 bytes.. */
    ret = net_receive(dcc->handle, dcc->read_buf+dcc->read_pos, 4-dcc->read_pos);
    if (ret == -1)
    {
        signal_emit("dcc closed", 1, dcc);
        dcc_destroy(dcc);
        return;
    }

    dcc->read_pos += ret;

    if (dcc->read_pos == 4)
    {
        bytes = 0; memcpy(&bytes, dcc->read_buf, 4);
        bytes = (guint32) ntohl(bytes);

        dcc->gotalldata = bytes == dcc->transfd;
        dcc->read_pos = 0;

        if (!dcc->fastsend)
        {
            /* send more data.. */
            dcc_send_data(dcc);
        }

        if (dcc->waitforend && dcc->gotalldata)
        {
            /* file is sent */
            signal_emit("dcc closed", 1, dcc);
            dcc_destroy(dcc);
            return;
        }
    }
}

/* input function: DCC SEND - someone tried to connect to our socket */
static void dcc_send_init(DCC_REC *dcc)
{
    gint handle, port;
    IPADDR addr;

    g_return_if_fail(dcc != NULL);

    /* accept connection */
    handle = net_accept(dcc->handle, &addr, &port);
    if (handle == -1)
        return;

    /* FIXME: add paranoia checking, check if host ip is the same as to who
       we sent the DCC SEND request.. */

    g_source_remove(dcc->tagread);
    close(dcc->handle);

    dcc->fastsend = settings_get_bool("dcc_fast_send");
    dcc->handle = handle;
    memcpy(&dcc->addr, &addr, sizeof(IPADDR));
    net_ip2host(&dcc->addr, dcc->addrstr);
    dcc->port = port;
    dcc->databufsize = settings_get_int("dcc_block_size") > 0 ? settings_get_int("dcc_block_size") : 2048;
    dcc->databuf = g_malloc(dcc->databufsize);
    dcc->starttime = time(NULL);
    dcc->tagread = g_input_add(handle, G_INPUT_READ,
			       (GInputFunction) dcc_send_read_size, dcc);
    dcc->tagwrite = !dcc->fastsend ? -1 :
	g_input_add(handle, G_INPUT_WRITE, (GInputFunction) dcc_send_data, dcc);

    signal_emit("dcc connected", 1, dcc);

    if (!dcc->fastsend)
    {
        /* send first block */
        dcc->gotalldata = TRUE;
        dcc_send_data(dcc);
    }
}

/* command: DCC SEND */
static void cmd_dcc_send(gchar *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
    gchar *params, *target, *fname, *str, *ptr;
    gint fh, h, port;
    glong fsize;
    DCC_REC *dcc, *chat;
    IPADDR addr;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &fname);

    /* if we're in dcc chat, send the request via it. */
    chat = irc_item_dcc_chat(item);

    if (chat != NULL && (chat->mirc_ctcp || g_strcasecmp(target, chat->nick) != 0))
        chat = NULL;

    if ((server == NULL || !server->connected) && chat == NULL)
        cmd_param_error(CMDERR_NOT_CONNECTED);

    if (*target == '\0' || *fname == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

    if (dcc_find_item(DCC_TYPE_SEND, target, fname))
    {
        signal_emit("dcc error send exists", 2, target, fname);
        g_free(params);
        return;
    }

    str = convert_home(fname);
    if (*str != '/')
    {
        gchar *path;

        g_free(str);
        path = convert_home(settings_get_str("dcc_upload_path"));
        str = g_strconcat(path, "/", fname, NULL);
        g_free(path);
    }

    fh = open(str, O_RDONLY);
    g_free(str);

    if (fh == -1)
    {
	signal_emit("dcc error file not found", 2, target, fname);
	g_free(params);
        return;
    }
    fsize = lseek(fh, 0, SEEK_END);
    lseek(fh, 0, SEEK_SET);

    /* get the IP address we use with IRC server */
    if (net_getsockname(chat != NULL ? chat->handle : server->handle, &addr, NULL) == -1)
    {
        close(fh);
        cmd_param_error(CMDERR_GETSOCKNAME);
    }

    /* start listening */
    port = settings_get_int("dcc_port");
    h = net_listen(&addr, &port);
    if (h == -1)
    {
        close(fh);
        cmd_param_error(CMDERR_LISTEN);
    }

    /* skip path */
    ptr = strrchr(fname, '/');
    if (ptr != NULL) fname = ptr+1;

    /* change all spaces to _ */
    fname = g_strdup(fname);
    for (ptr = fname; *ptr != '\0'; ptr++)
        if (*ptr == ' ') *ptr = '_';

    dcc = dcc_create(DCC_TYPE_SEND, h, target, fname, server, chat);
    dcc->port = port;
    dcc->size = fsize;
    dcc->fhandle = fh;
    dcc->tagread = g_input_add(h, G_INPUT_READ,
			       (GInputFunction) dcc_send_init, dcc);

    /* send DCC request */
    str = g_strdup_printf("DCC SEND %s %s %d %lu",
			  fname, dcc_make_address(&addr), port, fsize);
    dcc_ctcp_message(target, server, chat, FALSE, str);
    g_free(str);

    g_free(fname);
    g_free(params);
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
