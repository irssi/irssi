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

typedef struct
{
	NET_CALLBACK func;
	void *data;

	int pipes[2];
	int port;
	IPADDR *my_ip;
	int tag;
}
SIMPLE_THREAD_REC;

/* nonblocking gethostbyname(), ip (IPADDR) + error (int, 0 = not error) is
   written to pipe when found PID of the resolver child is returned */
int net_gethostname_nonblock(const char *addr, int pipe)
{
	RESOLVED_IP_REC rec;
	const char *errorstr;
	int pid;

	g_return_val_if_fail(addr != NULL, FALSE);

	pid = fork();
	if (pid > 0) {
		/* parent */
		pidwait_add(pid);
		return pid;
	}

	if (pid != 0) {
		/* failed! */
		g_warning("net_connect_thread(): fork() failed! Using blocking resolving");
	}

	/* child */
	rec.error = net_gethostname(addr, &rec.ip);
	if (rec.error == 0) {
		errorstr = NULL;
	} else {
		errorstr = net_gethosterror(rec.error);
		rec.errlen = strlen(errorstr)+1;
	}

	write(pipe, &rec, sizeof(rec));
	if (rec.error != 0)
		write(pipe, errorstr, rec.errlen);

	if (pid == 0)
		_exit(99);

	/* we used blocking lookup */
	return 0;
}

/* get the resolved IP address */
int net_gethostbyname_return(int pipe, RESOLVED_IP_REC *rec)
{
	time_t maxwait;
	int len, ret;

	rec->error = -1;
	rec->errorstr = NULL;

	/* get ip+error - try for max. 1-2 seconds */
	fcntl(pipe, F_SETFL, O_NONBLOCK);

	maxwait = time(NULL)+2;
	len = 0;
	do {
		ret = read(pipe, (char *) rec+len, sizeof(*rec)-len);
		if (ret == -1) return -1;

		len += ret;
	} while (len < sizeof(*rec) && time(NULL) < maxwait);

	if (len < sizeof(*rec))
		return -1; /* timeout */

	if (rec->error) {
		/* read error string */
		rec->errorstr = g_malloc(rec->errlen);
                len = 0;
		do {
			ret = read(pipe, rec->errorstr+len, rec->errlen-len);
			if (ret == -1) break;
                        len += ret;
		} while (len < rec->errlen && time(NULL) < maxwait);

		if (len < rec->errlen) {
			/* just ignore the rest of the error message.. */
			rec->errorstr[len] = '\0';
		}
	}

	return 0;
}

/* Kill the resolver child */
void net_disconnect_nonblock(int pid)
{
	g_return_if_fail(pid > 0);

	kill(pid, SIGKILL);
}

static void simple_init(SIMPLE_THREAD_REC *rec, int handle)
{
	g_return_if_fail(rec != NULL);

	g_source_remove(rec->tag);

	if (net_geterror(handle) != 0) {
		/* failed */
		close(handle);
		handle = -1;
	}

	rec->func(handle, rec->data);
	g_free(rec);
}

static void simple_readpipe(SIMPLE_THREAD_REC *rec, int pipe)
{
	RESOLVED_IP_REC iprec;
	int handle;

	g_return_if_fail(rec != NULL);

	g_source_remove(rec->tag);

	net_gethostbyname_return(pipe, &iprec);
	g_free_not_null(iprec.errorstr);

	close(rec->pipes[0]);
	close(rec->pipes[1]);

	handle = iprec.error == -1 ? -1 :
		net_connect_ip(&iprec.ip, rec->port, rec->my_ip);

	g_free_not_null(rec->my_ip);

	if (handle == -1) {
		/* failed */
		rec->func(-1, rec->data);
		g_free(rec);
		return;
	}

	rec->tag = g_input_add(handle, G_INPUT_WRITE,
			       (GInputFunction) simple_init, rec);
}

/* Connect to server, call func when finished */
int net_connect_nonblock(const char *server, int port, const IPADDR *my_ip, NET_CALLBACK func, void *data)
{
	SIMPLE_THREAD_REC *rec;
	int fd[2];

	g_return_val_if_fail(server != NULL, FALSE);
	g_return_val_if_fail(func != NULL, FALSE);

	if (pipe(fd) != 0) {
		g_warning("net_connect_nonblock(): pipe() failed.");
		return FALSE;
	}

	/* start nonblocking host name lookup */
	net_gethostname_nonblock(server, fd[1]);

	rec = g_new0(SIMPLE_THREAD_REC, 1);
	rec->port = port;
	if (my_ip != NULL) {
		rec->my_ip = g_malloc(sizeof(IPADDR));
		memcpy(rec->my_ip, my_ip, sizeof(IPADDR));
	}
	rec->func = func;
	rec->data = data;
	rec->pipes[0] = fd[0];
	rec->pipes[1] = fd[1];
	rec->tag = g_input_add(fd[0], G_INPUT_READ, (GInputFunction) simple_readpipe, rec);

	return 1;
}
