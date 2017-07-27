/*
 capsicum.c : Capsicum sandboxing support

    Copyright (C) 2017 Edward Tomasz Napierala <trasz@FreeBSD.org>

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
#include "signals.h"
#include "commands.h"

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/nv.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <string.h>

static int symbiontfds[2];

gboolean capsicum_enabled(void)
{
	u_int mode;
	int error;

	error = cap_getmode(&mode);
	if (error != 0)
		return FALSE;

	if (mode == 0)
		return FALSE;

	return TRUE;
}

int capsicum_net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip)
{
	nvlist_t *nvl;
	int error, saved_errno, sock;

	/* Send request to the symbiont. */
	nvl = nvlist_create(0);
	nvlist_add_binary(nvl, "ip", ip, sizeof(*ip));
	nvlist_add_number(nvl, "port", port);
	if (my_ip != NULL) {
		/* nvlist_add_binary(3) can't handle NULL values. */
		nvlist_add_binary(nvl, "my_ip", my_ip, sizeof(*my_ip));
	}
	error = nvlist_send(symbiontfds[1], nvl);
	nvlist_destroy(nvl);
	if (error != 0) {
		g_warning("nvlist_send: %s", strerror(errno));
		return -1;
	}

	/* Receive response. */
	nvl = nvlist_recv(symbiontfds[1], 0);
	if (nvl == NULL) {
		g_warning("nvlist_recv: %s", strerror(errno));
		return -1;
	}
	if (nvlist_exists_descriptor(nvl, "sock")) {
		sock = nvlist_take_descriptor(nvl, "sock");
	} else {
		sock = -1;
	}
	saved_errno = nvlist_get_number(nvl, "errno");
	nvlist_destroy(nvl);
	errno = saved_errno;

	return sock;
}

static void cmd_capsicum(const char *data, SERVER_REC *server, void *item)
{
	command_runsub("capsicum", data, server, item);
}

static int start_symbiont(void)
{
	pid_t pid;
	nvlist_t *nvl;
	IPADDR *ip, *my_ip;
	int childfd, error, port, saved_errno, sock;

	error = socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, symbiontfds);
	if (error != 0) {
		g_warning("socketpair: %s", strerror(errno));
		return 1;
	}

	pid = pdfork(&childfd, PD_CLOEXEC);
	if (pid < 0) {
		g_warning("pdfork: %s", strerror(errno));
		return 1;
	}

	if (pid > 0) {
		close(symbiontfds[0]);
		return 0;
	}

	/* We're the child, running outside the Capsicum sandbox. */
	setproctitle("capsicum symbiont");
	close(symbiontfds[1]);
	close(0);
	close(1);
	close(2);
	for (;;) {
		/* Receive parameters from the main irssi process. */
		nvl = nvlist_recv(symbiontfds[0], 0);
		if (nvl == NULL)
			exit(1);
		ip = nvlist_get_binary(nvl, "ip", NULL);
		port = (int)nvlist_get_number(nvl, "port");
		if (nvlist_exists(nvl, "my_ip"))
			my_ip = nvlist_get_binary(nvl, "my_ip", NULL);
		else
			my_ip = NULL;

		/* Connect. */
		sock = net_connect_ip_handle(ip, port, my_ip);
		saved_errno = errno;

		/* Send back the socket fd. */
		nvlist_destroy(nvl);
		nvl = nvlist_create(0);

		if (sock != -1)
			nvlist_move_descriptor(nvl, "sock", sock);
		nvlist_add_number(nvl, "errno", saved_errno);
		error = nvlist_send(symbiontfds[0], nvl);
		if (error != 0)
			exit(1);
		nvlist_destroy(nvl);
	}
}

static void cmd_capsicum_enter(void)
{
	int error;

	error = start_symbiont();
	if (error != 0) {
		signal_emit("capability mode failed", 1, strerror(errno));
		return;
	}

	error = cap_enter();
	if (error != 0) {
		signal_emit("capability mode failed", 1, strerror(errno));
	} else {
		signal_emit("capability mode enabled", 0);
	}
}

static void cmd_capsicum_status(void)
{
	u_int mode;
	int error;

	error = cap_getmode(&mode);
	if (error != 0) {
		signal_emit("capability mode failed", 1, strerror(errno));
	} else if (mode == 0) {
		signal_emit("capability mode disabled", 0);
	} else {
		signal_emit("capability mode enabled", 0);
	}
}

void capsicum_init(void)
{

	command_bind("capsicum", NULL, (SIGNAL_FUNC) cmd_capsicum);
	command_bind("capsicum enter", NULL, (SIGNAL_FUNC) cmd_capsicum_enter);
	command_bind("capsicum status", NULL, (SIGNAL_FUNC) cmd_capsicum_status);
}

void capsicum_deinit(void)
{
	command_unbind("capsicum", (SIGNAL_FUNC) cmd_capsicum);
	command_unbind("capsicum enter", (SIGNAL_FUNC) cmd_capsicum_enter);
	command_unbind("capsicum status", (SIGNAL_FUNC) cmd_capsicum_status);
}
