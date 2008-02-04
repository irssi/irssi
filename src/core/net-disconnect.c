/*
 net-disconnect.c :

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "network.h"

/* when quitting, wait for max. 5 seconds before forcing to close the socket */
#define MAX_QUIT_CLOSE_WAIT 5

/* wait for max. 2 minutes for other side to close the socket */
#define MAX_CLOSE_WAIT (60*2)

typedef struct {
	time_t created;
	GIOChannel *handle;
	int tag;
} NET_DISCONNECT_REC;

static GSList *disconnects;

static int timeout_tag;

static void net_disconnect_remove(NET_DISCONNECT_REC *rec)
{
	disconnects = g_slist_remove(disconnects, rec);

	g_source_remove(rec->tag);
        net_disconnect(rec->handle);
	g_free(rec);
}

static void sig_disconnect(NET_DISCONNECT_REC *rec)
{
	char buf[512];
	int count, ret;

	/* check if there's any data waiting in socket. read max. 5kB so
	   if server just keeps sending us stuff we won't get stuck */
	count = 0;
	do {
		ret = net_receive(rec->handle, buf, sizeof(buf));
		if (ret == -1) {
			/* socket was closed */
			net_disconnect_remove(rec);
		}
                count++;
	} while (ret == sizeof(buf) && count < 10);
}

static int sig_timeout_disconnect(void)
{
	NET_DISCONNECT_REC *rec;
	GSList *tmp, *next;
	time_t now;

	/* check if we've waited enough for sockets to close themselves */
	now = time(NULL);
	for (tmp = disconnects; tmp != NULL; tmp = next) {
		rec = tmp->data;
		next = tmp->next;

		if (rec->created+MAX_CLOSE_WAIT <= now)
			net_disconnect_remove(rec);
	}

	if (disconnects == NULL) {
		/* no more sockets in disconnect queue, stop calling this
		   function */
		timeout_tag = -1;
	}
	return disconnects != NULL;
}

/* Try to let the other side close the connection, if it still isn't
   disconnected after certain amount of time, close it ourself */
void net_disconnect_later(GIOChannel *handle)
{
	NET_DISCONNECT_REC *rec;

	rec = g_new(NET_DISCONNECT_REC, 1);
	rec->created = time(NULL);
	rec->handle = handle;
	rec->tag = g_input_add(handle, G_INPUT_READ,
			       (GInputFunction) sig_disconnect, rec);

	if (timeout_tag == -1) {
		timeout_tag = g_timeout_add(10000, (GSourceFunc)
					    sig_timeout_disconnect, NULL);
	}

	disconnects = g_slist_append(disconnects, rec);
}

void net_disconnect_init(void)
{
	disconnects = NULL;
	timeout_tag = -1;
}

void net_disconnect_deinit(void)
{
#ifndef WIN32
	NET_DISCONNECT_REC *rec;
	time_t now, max;
	int first, fd;
	struct timeval tv;
	fd_set set;

	/* give the sockets a chance to disconnect themselves.. */
	max = time(NULL)+MAX_QUIT_CLOSE_WAIT;
	first = 1;
	while (disconnects != NULL) {
		rec = disconnects->data;

		now = time(NULL);
		if (rec->created+MAX_QUIT_CLOSE_WAIT <= now || max <= now) {
			/* this one has waited enough */
			net_disconnect_remove(rec);
			continue;
		}

                fd = g_io_channel_unix_get_fd(rec->handle);
		FD_ZERO(&set);
		FD_SET(fd, &set);
		tv.tv_sec = first ? 0 : max-now;
		tv.tv_usec = first ? 100000 : 0;
		if (select(fd+1, &set, NULL, NULL, &tv) > 0 &&
		    FD_ISSET(fd, &set)) {
			/* data coming .. check if we can close the handle */
			sig_disconnect(rec);
		} else if (first) {
			/* Display the text when we have already waited
			   for a while */
			printf("Please wait, waiting for servers to close "
			       "connections..\n");
			fflush(stdout);

			first = 0;
		}
	}
#endif
}
