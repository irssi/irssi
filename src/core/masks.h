#ifndef __MASKS_H
#define __MASKS_H

int mask_match(SERVER_REC *server, const char *mask,
	       const char *nick, const char *user, const char *host);
int mask_match_address(SERVER_REC *server, const char *mask,
		       const char *nick, const char *address);
int masks_match(SERVER_REC *server, const char *masks,
		const char *nick, const char *address);

#endif
