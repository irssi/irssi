#ifndef __HILIGHT_TEXT_H
#define __HILIGHT_TEXT_H

typedef struct {
	char *text;

	char **channels; /* if non-NULL, check the text only from these channels */
	int level; /* match only messages with this level, 0=default */
	char *color; /* if starts with number, \003 is automatically
	                inserted before it. */

	int nickmask:1; /* `text 'is a nick mask - colorify the nick */
	int fullword:1; /* match `text' only for full words */
	int regexp:1; /* `text' is a regular expression */
} HILIGHT_REC;

extern GSList *hilights;

void hilight_text_init(void);
void hilight_text_deinit(void);

#endif
