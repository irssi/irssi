#include "module.h"

MODULE = Irssi::Masks  PACKAGE = Irssi
PROTOTYPES: ENABLE

int
mask_match(mask, nick, user, host)
	char *mask
	char *nick
	char *user
	char *host
CODE:
	RETVAL = mask_match(NULL, mask, nick, user, host);
OUTPUT:
	RETVAL

int
mask_match_address(mask, nick, address)
	char *mask
	char *nick
	char *address
CODE:
	RETVAL = mask_match_address(NULL, mask, nick, address);
OUTPUT:
	RETVAL

int
masks_match(masks, nick, address)
	char *masks
	char *nick
	char *address
CODE:
	RETVAL = masks_match(NULL, masks, nick, address);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi::Masks	PACKAGE = Irssi::Server
#*******************************

int
mask_match(server, mask, nick, user, host)
	Irssi::Server server
	char *mask
	char *nick
	char *user
	char *host

int
mask_match_address(server, mask, nick, address)
	Irssi::Server server
	char *mask
	char *nick
	char *address

int
masks_match(server, masks, nick, address)
	Irssi::Server server
	char *masks
	char *nick
	char *address
