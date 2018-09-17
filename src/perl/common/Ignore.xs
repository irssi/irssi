#define PERL_NO_GET_CONTEXT
#include "module.h"

MODULE = Irssi::Ignore  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
ignores()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = ignores; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Ignore")));
	}

int
ignore_check(nick, host, channel, text, level)
	char *nick
	char *host
	char *channel
	char *text
	int level
CODE:
	RETVAL = ignore_check(NULL, nick, host, channel, text, level);
OUTPUT:
	RETVAL

int
ignore_check_flags(nick, host, channel, text, level, flags)
	char *nick
	char *host
	char *channel
	char *text
	int level
	int flags
CODE:
	RETVAL = ignore_check_flags(NULL, nick, host, channel, text, level, flags);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi::Ignore  PACKAGE = Irssi::Server
#*******************************

int
ignore_check(server, nick, host, channel, text, level)
	Irssi::Server server
	char *nick
	char *host
	char *channel
	char *text
	int level

int
ignore_check_flags(server, nick, host, channel, text, level, flags)
	Irssi::Server server
	char *nick
	char *host
	char *channel
	char *text
	int level
	int flags

#*******************************
MODULE = Irssi::Ignore  PACKAGE = Irssi::Ignore  PREFIX = ignore_
#*******************************

void
ignore_add_rec(rec)
	Irssi::Ignore rec

void
ignore_update_rec(rec)
	Irssi::Ignore rec
