#include "module.h"
#include "ctcp.h"

MODULE = Irssi::Irc::Ctcp	PACKAGE = Irssi
PROTOTYPES: ENABLE

void
ctcp_register(name)
	char *name

void
ctcp_unregister(name)
	char *name

MODULE = Irssi::Irc::Ctcp	PACKAGE = Irssi::Irc::Server  PREFIX = irc_server_

void
ctcp_send_reply(server, data)
	Irssi::Irc::Server server
	char *data
