#include "module.h"

MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

PROTOTYPES: ENABLE

INCLUDE: Bans.xs
INCLUDE: IrcServer.xs
INCLUDE: IrcChannel.xs
INCLUDE: IrcQuery.xs
INCLUDE: Modes.xs
INCLUDE: Netsplit.xs

INCLUDE: Dcc.xs
INCLUDE: Flood.xs
INCLUDE: Notifylist.xs
