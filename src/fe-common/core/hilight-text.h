#ifndef __HILIGHT_TEXT_H
#define __HILIGHT_TEXT_H

typedef struct {
	char *text;

	char **channels; /* if non-NULL, check the text only from these channels */
	int level; /* match only messages with this level, 0=default */
	char *color; /* if starts with number, \003 is automatically
	                inserted before it. */

	unsigned int nick:1; /* hilight only the nick, not a full line - works only with msgs. */
	unsigned int nickmask:1; /* `text 'is a nick mask - colorify the nick */
	unsigned int fullword:1; /* match `text' only for full words */
	unsigned int regexp:1; /* `text' is a regular expression */
} HILIGHT_REC;

extern GSList *hilights;

char *hilight_match(const char *channel, const char *nickmask,
		    int level, const char *str);

char *hilight_find_nick(const char *channel, const char *nick,
			const char *address, int level, const char *msg);
int hilight_last_nick_color(void);

void hilight_text_init(void);
void hilight_text_deinit(void);

#endif
