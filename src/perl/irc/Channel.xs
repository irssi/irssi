#include "module.h"

MODULE = Irssi::Irc::Channel	PACKAGE = Irssi::Irc  PREFIX = irc_
PROTOTYPES: ENABLE

char *
irc_get_mask(nick, address, flags)
	char *nick
	char *address
	int flags

int
MASK_NICK()
CODE:
	RETVAL = IRC_MASK_NICK;
OUTPUT:
	RETVAL

int
MASK_USER()
CODE:
	RETVAL = IRC_MASK_USER;
OUTPUT:
	RETVAL

int
MASK_HOST()
CODE:
	RETVAL = IRC_MASK_HOST;
OUTPUT:
	RETVAL

int
MASK_DOMAIN()
CODE:
	RETVAL = IRC_MASK_DOMAIN;
OUTPUT:
	RETVAL

MODULE = Irssi::Irc::Channel	PACKAGE = Irssi::Irc::Channel  PREFIX = irc_

void
bans(channel)
	Irssi::Irc::Channel channel
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Irc::Ban")));
	}

Irssi::Irc::Nick
irc_nick_insert(channel, nick, op, halfop, voice, send_massjoin)
	Irssi::Irc::Channel channel
	char *nick
	int op
	int halfop
	int voice
	int send_massjoin
CODE:
	RETVAL = irc_nicklist_insert(channel, nick, op, halfop, voice, send_massjoin, NULL);
OUTPUT:
	RETVAL
