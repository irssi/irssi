MODULE = Irssi  PACKAGE = Irssi

int
irc_mask_match(mask, nick, user, host)
	char *mask
	char *nick
	char *user
	char *host

int
irc_mask_match_address(mask, nick, address)
	char *mask
	char *nick
	char *address

int
irc_masks_match(masks, nick, address)
	char *masks
	char *nick
	char *address

char *
irc_get_mask(nick, host, flags)
	char *nick
	char *host
	int flags
