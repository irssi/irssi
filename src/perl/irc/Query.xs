#include "module.h"

MODULE = Irssi::Irc::Query	PACKAGE = Irssi::Irc::Server  PREFIX = irc_
PROTOTYPES: ENABLE

Irssi::Irc::Query
irc_query_create(server_tag, nick, automatic)
	char *server_tag
	char *nick
	int automatic
