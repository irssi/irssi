#include "module.h"

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Server  PREFIX = irc_server_
PROTOTYPES: ENABLE

char *
irc_server_get_channels(server)
	Irssi::Irc::Server server

void
send_raw(server, cmd)
	Irssi::Irc::Server server
	char *cmd
CODE:
	irc_send_cmd(server, cmd);

void
send_raw_now(server, cmd)
	Irssi::Irc::Server server
	char *cmd
CODE:
	irc_send_cmd_now(server, cmd);

void
send_raw_split(server, cmd, nickarg, max_nicks)
	Irssi::Irc::Server server
	char *cmd
	int nickarg
	int max_nicks
CODE:
	irc_send_cmd_split(server, cmd, nickarg, max_nicks);

void
ctcp_send_reply(server, data)
	Irssi::Irc::Server server
	char *data

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Server  PREFIX = server_

void
server_redirect_register(command, remote, timeout, ...)
	char *command
	int remote
	int timeout
PREINIT:
        STRLEN n_a;
	GSList *start, *stop, **list;
	int n;
CODE:
	start = stop = NULL; list = &start;
	for (n = 3; n < items; n++) {
		if (ST(n) == &PL_sv_undef) list = &stop;
		if (SvPOK(ST(n)))
			*list = g_slist_append(*list, SvPV(ST(n), n_a));
	}
	server_redirect_register_list(command, remote, timeout, start, stop);

void
server_redirect_event(server, command, arg, remote, failure_signal, ...)
	Irssi::Irc::Server server
	char *command
	char *arg
	int remote
	char *failure_signal
PREINIT:
        STRLEN n_a;
	GSList *list;
	int n;
CODE:
	list = NULL;
	for (n = 5; n < items; n++) {
		list = g_slist_append(list, SvPV(ST(n), n_a));
	}
	server_redirect_event_list(server, command, arg, remote, failure_signal, list);

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Connect  PREFIX = irc_server_

Irssi::Irc::Server
irc_server_connect(conn)
	Irssi::Irc::Connect conn
