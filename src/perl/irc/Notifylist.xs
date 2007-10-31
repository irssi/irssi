#include "module.h"

MODULE = Irssi::Irc::Notifylist  PACKAGE = Irssi::Irc
PROTOTYPES: ENABLE

void
notifies()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = notifies; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Irc::Notifylist")));
	}

Irssi::Irc::Notifylist
notifylist_add(mask, ircnets, away_check, idle_check_time)
	char *mask
	char *ircnets
	int away_check
	int idle_check_time
CODE:
	if (idle_check_time != 0)
		croak("Notify -idle has been removed");
	RETVAL = notifylist_add(mask, ircnets, away_check);
OUTPUT:
	RETVAL

void
notifylist_remove(mask)
	char *mask

Irssi::Irc::Server
notifylist_ison(nick, serverlist)
	char *nick
	char *serverlist

Irssi::Irc::Notifylist
notifylist_find(mask, ircnet)
	char *mask
	char *ircnet

#*******************************
MODULE = Irssi::Irc::Notifylist  PACKAGE = Irssi::Irc::Server
#*******************************

int
notifylist_ison_server(server, nick)
	Irssi::Irc::Server server
	char *nick

#*******************************
MODULE = Irssi::Irc::Notifylist	PACKAGE = Irssi::Irc::Notifylist  PREFIX = notifylist_
#*******************************

int
notifylist_ircnets_match(rec, ircnet)
	Irssi::Irc::Notifylist rec
	char *ircnet
