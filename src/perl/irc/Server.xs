#define PERL_NO_GET_CONTEXT
#include "module.h"
#include <irssi/src/core/misc.h>

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

	if (hv == NULL)
		return NULL;

	list = NULL;
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL) {
		I32 len;
		char *key = hv_iterkey(he, &len);
		char *value = SvPV_nolen(HeVAL(he));

		list = g_slist_append(list, g_strdup(key));
		list = g_slist_append(list, g_strdup(value));
	}
	return list;
}

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Server  PREFIX = irc_server_
PROTOTYPES: ENABLE

void
irc_server_get_channels(server, rejoin_channels_mode = "")
	Irssi::Irc::Server server
	char *rejoin_channels_mode
PREINIT:
	char *ret;
	int mode;
	SETTINGS_REC *setting;
PPCODE:
	setting = settings_get_record("rejoin_channels_on_reconnect");
	mode = strarray_find(setting->choices, rejoin_channels_mode);
	if (mode < 0)
		mode = setting->default_value.v_int;

	ret = irc_server_get_channels(server, mode);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free(ret);

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
send_raw_first(server, cmd)
	Irssi::Irc::Server server
	char *cmd
CODE:
	irc_send_cmd_first(server, cmd);

void
send_raw_later(server, cmd)
	Irssi::Irc::Server server
	char *cmd
CODE:
	irc_send_cmd_later(server, cmd);

void
send_raw_split(server, cmd, nickarg, max_nicks)
	Irssi::Irc::Server server
	char *cmd
	int nickarg
	int max_nicks
CODE:
	irc_send_cmd_split(server, cmd, nickarg, max_nicks);

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Server  PREFIX = server_

void
server_redirect_register(command, remote, timeout, start, stop, opt)
	char *command
	int remote
	int timeout
	SV *start
	SV *stop
	SV *opt
CODE:
	server_redirect_register_list(command, remote, timeout, register_hash2list(hvref(start)),
	                              register_hash2list(hvref(stop)),
	                              register_hash2list(hvref(opt)), 1);

void
server_redirect_event(server, command, count, arg, remote, failure_signal, signals)
	Irssi::Irc::Server server
	char *command
	int count
	char *arg
	int remote
	char *failure_signal
	SV *signals
CODE:
	server_redirect_event_list(server, command, count, *arg == '\0' ? NULL : arg, remote,
				   *failure_signal == '\0' ? NULL : failure_signal,
				   event_hash2list(hvref(signals)));

char *
server_redirect_get_signal(server, prefix, event, args)
	Irssi::Irc::Server server
	char *prefix
	char *event
	char *args
CODE:
	RETVAL = (char *) server_redirect_get_signal(server, prefix, event, args);
OUTPUT:
	RETVAL

char *
server_redirect_peek_signal(server, prefix, event, args)
	Irssi::Irc::Server server
	char *prefix
	char *event
	char *args
PREINIT:
	int redirection;
CODE:
	RETVAL = (char *) server_redirect_peek_signal(server, prefix, event, args, &redirection);
OUTPUT:
	RETVAL

char *
server_isupport(server, name)
	Irssi::Irc::Server server
	char *name
CODE:
	RETVAL = (char *) g_hash_table_lookup(server->isupport, name);
OUTPUT:
	RETVAL

int
irc_server_cap_toggle(server, cap, enable)
	Irssi::Irc::Server server
	char *cap
	int enable
CODE:
	RETVAL = irc_cap_toggle(server, cap, enable);
OUTPUT:
	RETVAL
