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

MODULE = Irssi::Irc::Server	PACKAGE = Irssi::Irc::Connect  PREFIX = irc_server_

Irssi::Irc::Server
irc_server_connect(conn)
	Irssi::Irc::Connect conn
