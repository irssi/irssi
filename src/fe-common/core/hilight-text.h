#ifndef IRSSI_FE_COMMON_CORE_HILIGHT_TEXT_H
#define IRSSI_FE_COMMON_CORE_HILIGHT_TEXT_H

#include <irssi/src/core/iregex.h>
#include <irssi/src/fe-common/core/formats.h>

struct _HILIGHT_REC {
	char *text;

	char **channels; /* if non-NULL, check the text only from these channels */
	int level; /* match only messages with this level, 0=default */
	char *color; /* if starts with number, \003 is automatically
	                inserted before it. */
        char *act_color; /* color for window activity */
	int priority;

	unsigned int nick:1; /* hilight only nick if possible */
	unsigned int word:1; /* hilight only word, not full line */

	unsigned int nickmask:1; /* `text' is a nick mask */
	unsigned int fullword:1; /* match `text' only for full words */
	unsigned int regexp:1; /* `text' is a regular expression */
	unsigned int case_sensitive:1;/* `text' must match case */
	Regex *preg;
	char *servertag;
};

extern GSList *hilights;

HILIGHT_REC *hilight_match(SERVER_REC *server, const char *channel,
			   const char *nick, const char *address,
			   int level, const char *str,
			   int *match_beg, int *match_end);

HILIGHT_REC *hilight_match_nick(SERVER_REC *server, const char *channel,
			 const char *nick, const char *address,
			 int level, const char *msg);

char *hilight_get_color(HILIGHT_REC *rec);
void hilight_update_text_dest(TEXT_DEST_REC *dest, HILIGHT_REC *rec);

void hilight_create(HILIGHT_REC *rec);
void hilight_remove(HILIGHT_REC *rec);

void hilight_text_init(void);
void hilight_text_deinit(void);

#endif
