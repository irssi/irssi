#ifndef __FE_MESSAGES_H
#define __FE_MESSAGES_H

/* convert _underlined_ and *bold* words (and phrases) to use real
   underlining or bolding */
char *expand_emphasis(WI_ITEM_REC *item, const char *text);

char *channel_get_nickmode(CHANNEL_REC *channel, const char *nick);

extern GHashTable *printnicks;

#endif
