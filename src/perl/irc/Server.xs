#include "module.h"

static GSList *register_hash2list(HV *hv)
{
	HE *he;
	GSList *list;

	if (hv == NULL)
		return NULL;

	list = NULL;
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL) {
		I32 len;
		char *key = hv_iterkey(he, &len);
		int value = (int)SvIV(HeVAL(he));

		list = g_slist_append(list, g_strdup(key));
		list = g_slist_append(list, GINT_TO_POINTER(value));
	}
	return list;
}

static GSList *event_hash2list(HV *hv)
{
	HE *he;
	GSList *list;
        STRLEN n_a;

	if (hv == NULL)
		return NULL;

	list = NULL;
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL) {
		I32 len;
		char *key = hv_iterkey(he, &len);
		char *value = SvPV(HeVAL(he), n_a);

		list = g_slist_append(list, g_strdup(key));
		list = g_slist_append(list, g_strdup(value));
	}
	return list;
}

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
server_redirect_register(command, remote, timeout, start, stop)
	char *command
	int remote
	int timeout
	void *start
	void *stop
CODE:
	server_redirect_register_list(command, remote, timeout, 
				      register_hash2list(hvref(ST(3))),
				      register_hash2list(hvref(ST(4))));

void
server_redirect_event(server, command, arg, remote, failure_signal, signals)
	Irssi::Irc::Server server
	char *command
	char *arg
	int remote
	char *failure_signal
	void *signals
CODE:
	server_redirect_event_list(server, command, arg, remote,
				   failure_signal,
				   event_hash2list(hvref(ST(5))));

char *
server_redirect_get_signal(server, event, args)
	Irssi::Irc::Server server
	char *event
	char *args
CODE:
	RETVAL = (char *) server_redirect_get_signal(server, event, args);
OUTPUT:
	RETVAL

char *
server_redirect_peek_signal(server, event, args)
	Irssi::Irc::Server server
	char *event
	char *args
CODE:
	RETVAL = (char *) server_redirect_peek_signal(server, event, args);
OUTPUT:
	RETVAL

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Connect  PREFIX = irc_server_

Irssi::Irc::Server
irc_server_connect(conn)
	Irssi::Irc::Connect conn
