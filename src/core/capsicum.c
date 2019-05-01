/*
 capsicum.c : Capsicum sandboxing support

    Copyright (C) 2017 Edward Tomasz Napierala <trasz@FreeBSD.org>

    This software was developed by SRI International and the University of
    Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
    ("CTSRD"), as part of the DARPA CRASH research programme.

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
#include <irssi/src/core/capsicum.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/log.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/network-openssl.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/filio.h>
#include <sys/nv.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <string.h>
#include <termios.h>

#define	OPCODE_CONNECT		1
#define	OPCODE_GETHOSTBYNAME	2

static char *irclogs_path;
static size_t irclogs_path_len;
static int irclogs_fd;
static int symbiontfds[2];
static int port_min;
static int port_max;

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
	nvlist_add_number(nvl, "opcode", OPCODE_CONNECT);
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

	if (sock == -1 && (port < port_min || port > port_max)) {
		g_warning("Access restricted to ports between %d and %d "
		    "due to capability mode",
		    port_min, port_max);
	}

	errno = saved_errno;

	return sock;
}

int capsicum_net_gethostbyname(const char *addr, IPADDR *ip4, IPADDR *ip6)
{
	nvlist_t *nvl;
	const IPADDR *received_ip4, *received_ip6;
	int error, ret, saved_errno;

	/* Send request to the symbiont. */
	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "opcode", OPCODE_GETHOSTBYNAME);
	nvlist_add_string(nvl, "addr", addr);
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

	received_ip4 = nvlist_get_binary(nvl, "ip4", NULL);
	received_ip6 = nvlist_get_binary(nvl, "ip6", NULL);
	memcpy(ip4, received_ip4, sizeof(*ip4));
	memcpy(ip6, received_ip6, sizeof(*ip6));

	ret = nvlist_get_number(nvl, "ret");
	saved_errno = nvlist_get_number(nvl, "errno");
	nvlist_destroy(nvl);
	errno = saved_errno;

	return ret;
}

int capsicum_open(const char *path, int flags, int mode)
{
	int fd;

	/* +1 is for the slash separating irclogs_path and the rest. */
	if (strlen(path) > irclogs_path_len + 1 &&
	    path[irclogs_path_len] == '/' &&
	    strncmp(path, irclogs_path, irclogs_path_len) == 0) {
		fd = openat(irclogs_fd, path + irclogs_path_len + 1,
		    flags, mode);
	} else {
		fd = open(path, flags, mode);
	}

	if (fd < 0 && (errno == ENOTCAPABLE || errno == ECAPMODE))
		g_warning("File system access restricted to %s "
		    "due to capability mode", irclogs_path);

	return (fd);
}

int capsicum_open_wrapper(const char *path, int flags, int mode)
{
	if (capsicum_enabled()) {
		return capsicum_open(path, flags, mode);
	}
	return open(path, flags, mode);
}

void capsicum_mkdir_with_parents(const char *path, int mode)
{
	char *component, *copy, *tofree;
	int error, fd, newfd;

	/* The directory already exists, nothing to do. */
	if (strcmp(path, irclogs_path) == 0)
		return;

	/* +1 is for the slash separating irclogs_path and the rest. */
	if (strlen(path) <= irclogs_path_len + 1 ||
	    path[irclogs_path_len] != '/' ||
	    strncmp(path, irclogs_path, irclogs_path_len) != 0) {
		g_warning("Cannot create %s: file system access restricted "
		    "to %s due to capability mode", path, irclogs_path);
		return;
	}

	copy = tofree = g_strdup(path + irclogs_path_len + 1);
	fd = irclogs_fd;
	for (;;) {
		component = strsep(&copy, "/");
		if (component == NULL)
			break;
		error = mkdirat(fd, component, mode);
		if (error != 0 && errno != EEXIST) {
			g_warning("cannot create %s: %s",
			    component, strerror(errno));
			break;
		}
		newfd = openat(fd, component, O_DIRECTORY);
		if (newfd < 0) {
			g_warning("cannot open %s: %s",
			    component, strerror(errno));
			break;
		}
		if (fd != irclogs_fd)
			close(fd);
		fd = newfd;
	}
	g_free(tofree);
	if (fd != irclogs_fd)
		close(fd);
}

void capsicum_mkdir_with_parents_wrapper(const char *path, int mode)
{
	if (capsicum_enabled()) {
		capsicum_mkdir_with_parents(path, mode);
		return;
	}
	g_mkdir_with_parents(path, mode);
}

nvlist_t *symbiont_connect(const nvlist_t *request)
{
	nvlist_t *response;
	const IPADDR *ip, *my_ip;
	int port, saved_errno, sock;

	ip = nvlist_get_binary(request, "ip", NULL);
	port = (int)nvlist_get_number(request, "port");
	if (nvlist_exists(request, "my_ip"))
		my_ip = nvlist_get_binary(request, "my_ip", NULL);
	else
		my_ip = NULL;

	/*
	 * Check if the port is in allowed range.  This is to minimize
	 * the chance of the attacker rooting another system in case of
	 * compromise.
	 */
	if (port < port_min || port > port_max) {
		sock = -1;
		saved_errno = EPERM;
	} else {
		/* Connect. */
		sock = net_connect_ip_handle(ip, port, my_ip);
		saved_errno = errno;
	}

	/* Send back the socket fd. */
	response = nvlist_create(0);

	if (sock != -1)
		nvlist_move_descriptor(response, "sock", sock);
	nvlist_add_number(response, "errno", saved_errno);

	return (response);
}

nvlist_t *symbiont_gethostbyname(const nvlist_t *request)
{
	nvlist_t *response;
	IPADDR ip4, ip6;
	const char *addr;
	int ret, saved_errno;

	addr = nvlist_get_string(request, "addr");

	/* Connect. */
	ret = net_gethostbyname(addr, &ip4, &ip6);
	saved_errno = errno;

	/* Send back the IPs. */
	response = nvlist_create(0);

	nvlist_add_number(response, "ret", ret);
	nvlist_add_number(response, "errno", saved_errno);
	nvlist_add_binary(response, "ip4", &ip4, sizeof(ip4));
	nvlist_add_binary(response, "ip6", &ip6, sizeof(ip6));

	return (response);
}

/*
 * Child process, running outside the Capsicum sandbox.
 */
_Noreturn static void symbiont(void)
{
	nvlist_t *request, *response;
	int error, opcode;

	setproctitle("capsicum symbiont");
	close(symbiontfds[1]);
	close(0);
	close(1);
	close(2);

	for (;;) {
		/* Receive parameters from the main irssi process. */
		request = nvlist_recv(symbiontfds[0], 0);
		if (request == NULL)
			exit(1);

		opcode = nvlist_get_number(request, "opcode");
		switch (opcode) {
		case OPCODE_CONNECT:
			response = symbiont_connect(request);
			break;
		case OPCODE_GETHOSTBYNAME:
			response = symbiont_gethostbyname(request);
			break;
		default:
			exit(1);
		}

		/* Send back the response. */
		error = nvlist_send(symbiontfds[0], response);
		if (error != 0)
			exit(1);
		nvlist_destroy(request);
		nvlist_destroy(response);
	}
}

static int start_symbiont(void)
{
	int childfd, error;
	pid_t pid;

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

	symbiont();
	/* NOTREACHED */
}

static void cmd_capsicum(const char *data, SERVER_REC *server, void *item)
{
	command_runsub("capsicum", data, server, item);
}

/*
 * The main difference between this and caph_limit_stdio(3) is that this
 * one permits TIOCSETAW, which is requred for restoring the terminal state
 * on exit.
 */
static int
limit_stdio_fd(int fd)
{
	cap_rights_t rights;
	unsigned long cmds[] = { TIOCGETA, TIOCGWINSZ, TIOCSETAW, FIODTYPE };

	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_FCNTL,
	    CAP_FSTAT, CAP_IOCTL, CAP_SEEK);

	if (cap_rights_limit(fd, &rights) < 0) {
		g_warning("cap_rights_limit(3) failed: %s", strerror(errno));
		return (-1);
	}

	if (cap_ioctls_limit(fd, cmds, nitems(cmds)) < 0) {
		g_warning("cap_ioctls_limit(3) failed: %s", strerror(errno));
		return (-1);
	}

	if (cap_fcntls_limit(fd, CAP_FCNTL_GETFL) < 0) {
		g_warning("cap_fcntls_limit(3) failed: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

static void cmd_capsicum_enter(void)
{
	u_int mode;
	gboolean inited;
	int error;

	error = cap_getmode(&mode);
	if (error == 0 && mode != 0) {
		g_warning("Already in capability mode");
		return;
	}

	inited = irssi_ssl_init();
	if (!inited) {
		signal_emit("capability mode failed", 1, strerror(errno));
		return;
	}

	port_min = settings_get_int("capsicum_port_min");
	port_max = settings_get_int("capsicum_port_max");

	irclogs_path = convert_home(settings_get_str("capsicum_irclogs_path"));
	irclogs_path_len = strlen(irclogs_path);

	/* Strip trailing slashes, if any. */
	while (irclogs_path_len > 0 && irclogs_path[irclogs_path_len - 1] == '/') {
		irclogs_path[irclogs_path_len - 1] = '\0';
		irclogs_path_len--;
	}

	g_mkdir_with_parents(irclogs_path, log_dir_create_mode);
	irclogs_fd = open(irclogs_path, O_DIRECTORY | O_CLOEXEC);
	if (irclogs_fd < 0) {
		g_warning("Unable to open %s: %s", irclogs_path, strerror(errno));
		signal_emit("capability mode failed", 1, strerror(errno));
		return;
	}

	error = start_symbiont();
	if (error != 0) {
		signal_emit("capability mode failed", 1, strerror(errno));
		return;
	}

	/*
	 * XXX: We should use pdwait(2) to wait for children.  Unfortunately
	 *      it's not implemented yet.  Thus the workaround, to get rid
	 *      of the zombies at least.
	 */
	signal(SIGCHLD, SIG_IGN);

	if (limit_stdio_fd(STDIN_FILENO) != 0 ||
	    limit_stdio_fd(STDOUT_FILENO) != 0 ||
	    limit_stdio_fd(STDERR_FILENO) != 0) {
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

void sig_init_finished(void)
{
	if (settings_get_bool("capsicum"))
		cmd_capsicum_enter();
}

void capsicum_init(void)
{
	settings_add_bool("misc", "capsicum", FALSE);
	settings_add_str("misc", "capsicum_irclogs_path", "~/irclogs");
	settings_add_int("misc", "capsicum_port_min", 6667);
	settings_add_int("misc", "capsicum_port_max", 9999);

	signal_add("irssi init finished", (SIGNAL_FUNC) sig_init_finished);

	command_bind("capsicum", NULL, (SIGNAL_FUNC) cmd_capsicum);
	command_bind("capsicum enter", NULL, (SIGNAL_FUNC) cmd_capsicum_enter);
	command_bind("capsicum status", NULL, (SIGNAL_FUNC) cmd_capsicum_status);
}

void capsicum_deinit(void)
{
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);

	command_unbind("capsicum", (SIGNAL_FUNC) cmd_capsicum);
	command_unbind("capsicum enter", (SIGNAL_FUNC) cmd_capsicum_enter);
	command_unbind("capsicum status", (SIGNAL_FUNC) cmd_capsicum_status);
}
