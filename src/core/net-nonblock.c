/*
 net-nonblock.c : Nonblocking net_connect()

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

#include <signal.h>

#include "pidwait.h"
#include "net-nonblock.h"

typedef struct {
	NET_CALLBACK func;
	void *data;

	GIOChannel *pipes[2];
	int port;
	IPADDR *my_ip;
	int tag;
} SIMPLE_THREAD_REC;

#define is_fatal_error(err) \
	(err != 0 && err != G_IO_ERROR_AGAIN && errno != EINTR)

static int g_io_channel_write_block(GIOChannel *channel, void *data, int len)
{
        unsigned int ret;
	int err, sent;

	sent = 0;
	do {
		err = g_io_channel_write(channel, (char *) data + sent,
					 len-sent, &ret);
                sent += ret;
	} while (sent < len && !is_fatal_error(err));

	return err != 0 ? -1 : 0;
}

static int g_io_channel_read_block(GIOChannel *channel, void *data, int len)
{
	time_t maxwait;
        unsigned int ret;
	int err, received;

	maxwait = time(NULL)+2;
	received = 0;
	do {
		err = g_io_channel_read(channel, (char *) data + received,
					len-received, &ret);
		received += ret;
	} while (received < len && time(NULL) < maxwait &&
		 (ret != 0 || !is_fatal_error(err)));

	return received < len ? -1 : 0;
}

/* nonblocking gethostbyname(), ip (IPADDR) + error (int, 0 = not error) is
   written to pipe when found PID of the resolver child is returned */
int net_gethostbyname_nonblock(const char *addr, GIOChannel *pipe)
{
	RESOLVED_IP_REC rec;
	const char *errorstr;
#ifndef WIN32
	int pid;
#endif

	g_return_val_if_fail(addr != NULL, FALSE);

#ifndef WIN32
	pid = fork();
	if (pid > 0) {
		/* parent */
		pidwait_add(pid);
		return pid;
	}

	if (pid != 0) {
		/* failed! */
		g_warning("net_connect_thread(): fork() failed! "
			  "Using blocking resolving");
	}
#endif

	/* child */
        memset(&rec, 0, sizeof(rec));
	rec.error = net_gethostbyname(addr, &rec.ip4, &rec.ip6);
	if (rec.error == 0) {
		errorstr = NULL;
	} else {
		errorstr = net_gethosterror(rec.error);
		rec.errlen = errorstr == NULL ? 0 : strlen(errorstr)+1;
	}

        g_io_channel_write_block(pipe, &rec, sizeof(rec));
	if (rec.errlen != 0)
		g_io_channel_write_block(pipe, (void *) errorstr, rec.errlen);

#ifndef WIN32
	if (pid == 0)
		_exit(99);
#endif

	/* we used blocking lookup */
	return 0;
}

/* get the resolved IP address */
int net_gethostbyname_return(GIOChannel *pipe, RESOLVED_IP_REC *rec)
{
	rec->error = -1;
	rec->errorstr = NULL;

#ifndef WIN32
	fcntl(g_io_channel_unix_get_fd(pipe), F_SETFL, O_NONBLOCK);
#endif

	/* get ip+error */
	if (g_io_channel_read_block(pipe, rec, sizeof(*rec)) == -1) {
		rec->errorstr = g_strdup_printf("Host name lookup: %s",
						g_strerror(errno));
		return -1;
	}

	if (rec->error) {
		/* read error string, if we can't read everything for some
		   reason, just ignore it. */
		rec->errorstr = g_malloc0(rec->errlen+1);
                g_io_channel_read_block(pipe, rec->errorstr, rec->errlen);
	}

	return 0;
}

/* Get host name, call func when finished */
int net_gethostbyaddr_nonblock(IPADDR *ip, NET_HOST_CALLBACK func, void *data)
{
	/* FIXME: not implemented */
	return FALSE;
}

/* Kill the resolver child */
void net_disconnect_nonblock(int pid)
{
	g_return_if_fail(pid > 0);

#ifndef WIN32
	kill(pid, SIGKILL);
#endif
}

static void simple_init(SIMPLE_THREAD_REC *rec, GIOChannel *handle)
{
	g_return_if_fail(rec != NULL);

	g_source_remove(rec->tag);

	if (net_geterror(handle) != 0) {
		/* failed */
		g_io_channel_close(handle);
                g_io_channel_unref(handle);
		handle = NULL;
	}

	rec->func(handle, rec->data);
	g_free(rec);
}

static void simple_readpipe(SIMPLE_THREAD_REC *rec, GIOChannel *pipe)
{
	RESOLVED_IP_REC iprec;
	GIOChannel *handle;
	IPADDR *ip;

	g_return_if_fail(rec != NULL);

	g_source_remove(rec->tag);

	net_gethostbyname_return(pipe, &iprec);
	g_free_not_null(iprec.errorstr);

	g_io_channel_close(rec->pipes[0]);
	g_io_channel_unref(rec->pipes[0]);
	g_io_channel_close(rec->pipes[1]);
	g_io_channel_unref(rec->pipes[1]);

	ip = iprec.ip4.family != 0 ? &iprec.ip4 : &iprec.ip6;
	handle = iprec.error == -1 ? NULL :
		net_connect_ip(ip, rec->port, rec->my_ip);

	g_free_not_null(rec->my_ip);

	if (handle == NULL) {
		/* failed */
		rec->func(NULL, rec->data);
		g_free(rec);
		return;
	}

	rec->tag = g_input_add(handle, G_INPUT_READ | G_INPUT_WRITE,
			       (GInputFunction) simple_init, rec);
}

/* Connect to server, call func when finished */
int net_connect_nonblock(const char *server, int port, const IPADDR *my_ip,
			 NET_CALLBACK func, void *data)
{
	SIMPLE_THREAD_REC *rec;
	int fd[2];

	g_return_val_if_fail(server != NULL, FALSE);
	g_return_val_if_fail(func != NULL, FALSE);

	if (pipe(fd) != 0) {
		g_warning("net_connect_nonblock(): pipe() failed.");
		return FALSE;
	}

	rec = g_new0(SIMPLE_THREAD_REC, 1);
	rec->port = port;
	if (my_ip != NULL) {
		rec->my_ip = g_malloc(sizeof(IPADDR));
		memcpy(rec->my_ip, my_ip, sizeof(IPADDR));
	}
	rec->func = func;
	rec->data = data;
	rec->pipes[0] = g_io_channel_unix_new(fd[0]);
	rec->pipes[1] = g_io_channel_unix_new(fd[1]);

	/* start nonblocking host name lookup */
	net_gethostbyname_nonblock(server, rec->pipes[1]);
	rec->tag = g_input_add(rec->pipes[0], G_INPUT_READ,
			       (GInputFunction) simple_readpipe, rec);

	return TRUE;
}
