#ifndef IRSSI_IRC_CORE_IRC_MASKS_H
#define IRSSI_IRC_CORE_IRC_MASKS_H

#include <irssi/src/core/masks.h>

#define IRC_MASK_NICK   0x01
#define IRC_MASK_USER   0x02
#define IRC_MASK_HOST   0x04
#define IRC_MASK_DOMAIN 0x08

char *irc_get_mask(const char *nick, const char *address, int flags);

#endif
