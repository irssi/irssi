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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"

#include "network.h"
#include "net-sendbuffer.h"

struct _NET_SENDBUF_REC {
	GIOChannel *handle;

	int bufsize;
	int bufpos;
	char *buffer; /* Buffer is NULL until it's actually needed. */
};

static GSList *buffers;
static int timeout_tag;

/* Create new buffer - if `bufsize' is zero or less, DEFAULT_BUFFER_SIZE
   is used */
NET_SENDBUF_REC *net_sendbuffer_create(GIOChannel *handle, int bufsize)
{
	NET_SENDBUF_REC *rec;

	g_return_val_if_fail(handle != NULL, NULL);

	rec = g_new0(NET_SENDBUF_REC, 1);
	rec->handle = handle;
	rec->bufsize = bufsize > 0 ? bufsize : DEFAULT_BUFFER_SIZE;

	buffers = g_slist_append(buffers, rec);
	return rec;
}

/* Destroy the buffer. `close' specifies if socket handle should be closed. */
void net_sendbuffer_destroy(NET_SENDBUF_REC *rec, int close)
{
	buffers = g_slist_remove(buffers, rec);

	if (close) net_disconnect(rec->handle);
	g_free_not_null(rec->buffer);
	g_free(rec);
}

/* Transmit all data from buffer - return TRUE if successful */
static int buffer_send(NET_SENDBUF_REC *rec)
{
	int ret;

	ret = net_transmit(rec->handle, rec->buffer, rec->bufpos);
	if (ret < 0 || rec->bufpos == ret) {
		/* error/all sent - don't try to send it anymore */
                g_free_and_null(rec->buffer);
		return TRUE;
	}

	if (ret > 0) {
                rec->bufpos -= ret;
		memmove(rec->buffer, rec->buffer+ret, rec->bufpos);
	}
	return FALSE;
}

static int sig_sendbuffer(void)
{
	GSList *tmp;
	int stop;

	stop = TRUE;
	for (tmp = buffers; tmp != NULL; tmp = tmp->next) {
		NET_SENDBUF_REC *rec = tmp->data;

		if (rec->buffer != NULL) {
			if (!buffer_send(rec))
				stop = FALSE;
		}
	}

        if (stop) timeout_tag = -1;
	return !stop;
}

/* Add `data' to transmit buffer - return FALSE if buffer is full */
static int buffer_add(NET_SENDBUF_REC *rec, const void *data, int size)
{
	if (rec->buffer == NULL) {
		rec->buffer = g_malloc(rec->bufsize);
		rec->bufpos = 0;
	}

	if (rec->bufpos+size > rec->bufsize)
		return FALSE;

	memcpy(rec->buffer+rec->bufpos, data, size);
	rec->bufpos += size;
	return TRUE;
}

/* Send data, if all of it couldn't be sent immediately, it will be resent
   automatically after a while. Returns -1 if some unrecoverable error
   occured. */
int net_sendbuffer_send(NET_SENDBUF_REC *rec, const void *data, int size)
{
	int ret;

	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(data != NULL, -1);
	if (size <= 0) return 0;

	if (rec->buffer == NULL) {
                /* nothing in buffer - transmit immediately */
		ret = net_transmit(rec->handle, data, size);
		if (ret < 0) return -1;
		size -= ret;
		data = ((char *) data) + ret;
	}

	if (size > 0) {
		/* everything couldn't be sent. */
		if (timeout_tag == -1) {
			timeout_tag = g_timeout_add(100, (GSourceFunc)
						    sig_sendbuffer, NULL);
		}

		if (!buffer_add(rec, data, size))
			return -1;
	}

	return 0;
}

/* Returns the socket handle */
GIOChannel *net_sendbuffer_handle(NET_SENDBUF_REC *rec)
{
	g_return_val_if_fail(rec != NULL, NULL);

	return rec->handle;
}

void net_sendbuffer_init(void)
{
	timeout_tag = -1;
	buffers = NULL;
}

void net_sendbuffer_deinit(void)
{
	if (timeout_tag != -1) g_source_remove(timeout_tag);
}
