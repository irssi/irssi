#ifndef __MASKS_H
#define __MASKS_H

#define IRC_MASK_NICK   0x01
#define IRC_MASK_USER   0x02
#define IRC_MASK_HOST   0x04
#define IRC_MASK_DOMAIN 0x08

int irc_mask_match(const char *mask, const char *nick, const char *user, const char *host);
int irc_mask_match_address(const char *mask, const char *nick, const char *address);
int irc_masks_match(const char *masks, const char *nick, const char *address);

char *irc_get_mask(const char *nick, const char *address, int flags);

#endif
