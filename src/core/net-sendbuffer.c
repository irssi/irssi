/*
 net-sendbuffer.c : Buffered send()

    Copyright (C) 1998-2000 Timo Sirainen

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

#include <irssi/src/core/network.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/line-split.h>

/* Create new buffer - if `bufsize' is zero or less, DEFAULT_BUFFER_SIZE
   is used */
NET_SENDBUF_REC *net_sendbuffer_create(GIOChannel *handle, int bufsize)
{
	NET_SENDBUF_REC *rec;

	g_return_val_if_fail(handle != NULL, NULL);

	rec = g_new0(NET_SENDBUF_REC, 1);
        rec->send_tag = -1;
	rec->handle = handle;
	rec->bufsize = bufsize > 0 ? bufsize : DEFAULT_BUFFER_SIZE;
	rec->def_bufsize = rec->bufsize;

	return rec;
}

/* Destroy the buffer. `close' specifies if socket handle should be closed. */
void net_sendbuffer_destroy(NET_SENDBUF_REC *rec, int close)
{
        if (rec->send_tag != -1) g_source_remove(rec->send_tag);
	if (close) net_disconnect(rec->handle);
	if (rec->readbuffer != NULL) line_split_free(rec->readbuffer);
	g_free_not_null(rec->buffer);
	g_free(rec);
}

/* Transmit all data from buffer - return TRUE if the whole buffer was sent */
static int buffer_send(NET_SENDBUF_REC *rec)
{
	int ret;

	ret = net_transmit(rec->handle, rec->buffer, rec->bufpos);
	if (ret < 0 || rec->bufpos == ret) {
		/* error/all sent - don't try to send it anymore */
		rec->bufsize = rec->def_bufsize;
		rec->buffer = g_realloc(rec->buffer, rec->bufsize);
		rec->bufpos = 0;
		return TRUE;
	}

	if (ret > 0) {
                rec->bufpos -= ret;
		memmove(rec->buffer, rec->buffer+ret, rec->bufpos);
	}
	return FALSE;
}

static void sig_sendbuffer(NET_SENDBUF_REC *rec)
{
	if (rec->buffer != NULL) {
		if (!buffer_send(rec))
                        return;
	}

	g_source_remove(rec->send_tag);
	rec->send_tag = -1;
}

/* Add `data' to transmit buffer - return FALSE if buffer is full */
static int buffer_add(NET_SENDBUF_REC *rec, const void *data, int size)
{
	if (rec->buffer == NULL) {
		rec->buffer = g_malloc(rec->bufsize);
		rec->bufpos = 0;
	}

	while (rec->bufpos+size > rec->bufsize) {
		if (rec->bufsize >= MAX_BUFFER_SIZE) {
			if (!rec->dead)
				g_warning("Dropping some data on an outgoing connection");
			rec->dead = 1;
			return FALSE;
		}
		rec->bufsize *= 2;
		rec->buffer = g_realloc(rec->buffer, rec->bufsize);
	}

	memcpy(rec->buffer+rec->bufpos, data, size);
	rec->bufpos += size;
	return TRUE;
}

/* Send data, if all of it couldn't be sent immediately, it will be resent
   automatically after a while. Returns -1 if some unrecoverable error
   occurred. */
int net_sendbuffer_send(NET_SENDBUF_REC *rec, const void *data, int size)
{
	int ret;

	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	if (size <= 0) return 0;

	if (rec->buffer == NULL || rec->bufpos == 0) {
                /* nothing in buffer - transmit immediately */
		ret = net_transmit(rec->handle, data, size);
		if (ret < 0) return -1;
		size -= ret;
		data = ((const char *) data) + ret;
	}

	if (size <= 0)
		return 0;

	/* everything couldn't be sent. */
	if (rec->send_tag == -1) {
		rec->send_tag =
		    i_input_add(rec->handle, I_INPUT_WRITE, (GInputFunction) sig_sendbuffer, rec);
	}

	return buffer_add(rec, data, size) ? 0 : -1;
}

int net_sendbuffer_receive_line(NET_SENDBUF_REC *rec, char **str, int read_socket)
{
	char tmpbuf[2048];
	int recvlen = 0;

	if (read_socket)
		recvlen = net_receive(rec->handle, tmpbuf, sizeof(tmpbuf));

	return line_split(tmpbuf, recvlen, str, &rec->readbuffer);
}

/* Flush the buffer, blocks until finished. */
void net_sendbuffer_flush(NET_SENDBUF_REC *rec)
{
	int handle;

	if (rec->buffer == NULL)
		return;

        /* set the socket blocking while doing this */
	handle = g_io_channel_unix_get_fd(rec->handle);
	fcntl(handle, F_SETFL, 0);
	while (!buffer_send(rec)) ;
	fcntl(handle, F_SETFL, O_NONBLOCK);
}

/* Returns the socket handle */
GIOChannel *net_sendbuffer_handle(NET_SENDBUF_REC *rec)
{
	g_return_val_if_fail(rec != NULL, NULL);

	return rec->handle;
}
