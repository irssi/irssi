#include "module.h"

MODULE = Irssi::Irc::Netsplit	PACKAGE = Irssi::Irc::Server
PROTOTYPES: ENABLE

Irssi::Irc::Netsplit
netsplit_find(server, nick, address)
	Irssi::Irc::Server server
	char *nick
	char *address

Irssi::Irc::Netsplitchannel
netsplit_find_channel(server, nick, address, channel)
	Irssi::Irc::Server server
	char *nick
	char *address
	char *channel
