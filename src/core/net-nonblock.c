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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"

#include <signal.h>

#include <irssi/src/core/pidwait.h>
#include <irssi/src/core/net-nonblock.h>

/* nonblocking gethostbyname(), ip (IPADDR) + error (int, 0 = not error) is
   written to pipe when found PID of the resolver child is returned */
int net_gethostbyname_nonblock(const char *addr, GIOChannel *pipe, int reverse_lookup)
{
	RESOLVED_IP_REC rec;
	const char *errorstr;
	int pid;

	(void) reverse_lookup; /* Kept for API backward compatibility */

	g_return_val_if_fail(addr != NULL, FALSE);

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

	/* child */
	srand(time(NULL));

	memset(&rec, 0, sizeof(rec));
	rec.error = net_gethostbyname(addr, &rec.ip4, &rec.ip6);
	if (rec.error == 0) {
		errorstr = NULL;
	} else {
		errorstr = net_gethosterror(rec.error);
		rec.errlen = errorstr == NULL ? 0 : strlen(errorstr)+1;
	}

	i_io_channel_write_block(pipe, &rec, sizeof(rec));
	if (rec.errlen != 0)
		i_io_channel_write_block(pipe, (void *) errorstr, rec.errlen);

	if (pid == 0)
		_exit(99);

	/* we used blocking lookup */
	return 0;
}

/* get the resolved IP address */
int net_gethostbyname_return(GIOChannel *pipe, RESOLVED_IP_REC *rec)
{
	rec->error = -1;
	rec->errorstr = NULL;

	fcntl(g_io_channel_unix_get_fd(pipe), F_SETFL, O_NONBLOCK);

	/* get ip+error */
	if (i_io_channel_read_block(pipe, rec, sizeof(*rec)) == -1) {
		rec->errorstr = g_strdup_printf("Host name lookup: %s",
						g_strerror(errno));
		return -1;
	}

	if (rec->error) {
		/* read error string, if we can't read everything for some
		   reason, just ignore it. */
		rec->errorstr = g_malloc0(rec->errlen+1);
		i_io_channel_read_block(pipe, rec->errorstr, rec->errlen);
	}

	return 0;
}

/* Kill the resolver child */
void net_disconnect_nonblock(int pid)
{
	g_return_if_fail(pid > 0);

	kill(pid, SIGKILL);
}
