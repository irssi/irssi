#ifndef __IRC_HILIGHT_TEXT_H
#define __IRC_HILIGHT_TEXT_H

char *irc_hilight_find_nick(const char *channel, const char *nick,
			    const char *address, int level, const char *msg);

int irc_hilight_last_color(void);

#endif
