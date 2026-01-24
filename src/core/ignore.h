#ifndef IRSSI_CORE_IGNORE_H
#define IRSSI_CORE_IGNORE_H

#include <irssi/src/core/iregex.h>

typedef struct _IGNORE_REC IGNORE_REC;

struct _IGNORE_REC {
	int level; /* ignore these levels */
	char *mask; /* nick mask */
	char *servertag; /* this is for autoignoring */
	char *comment;   /* comment, for internal use only */
	char **channels; /* ignore only in these channels */
	char *pattern; /* text body must match this pattern */

        time_t unignore_time; /* time in sec for temp ignores */

	unsigned int exception:1; /* *don't* ignore */
	unsigned int regexp:1;
	unsigned int fullword:1;
	unsigned int replies:1; /* ignore replies to nick in channel */
	Regex *preg;
};

extern GSList *ignores;

int ignore_check(SERVER_REC *server, const char *nick, const char *host,
		 const char *channel, const char *text, int level);
int ignore_check_flags(SERVER_REC *server, const char *nick, const char *host,
		       const char *channel, const char *text, int level, int flags);
int ignore_check_plus(SERVER_REC *server, const char *nick, const char *host,
		      const char *channel, const char *text, int *level, int test_ignore);

enum {
	IGNORE_FIND_PATTERN = 0x01,   /* Match the pattern */
	IGNORE_FIND_NO_ACT = 0x02,    /* Find the targets with NO_ACT level */
	IGNORE_FIND_HIDDEN = 0x04,    /* Find the targets with HIDDEN level */
	IGNORE_FIND_NOHILIGHT = 0x08, /* Find the targets with NOHILIGHT level */
	IGNORE_FIND_EXCEPT = 0x10,    /* Find negated ignore */
	IGNORE_FIND_ANY = 0x20,       /* Find ignore based on mask only */
};

IGNORE_REC *ignore_find_full (const char *servertag, const char *mask, const char *pattern,
                char **channels, const int flags);

void ignore_add_rec(IGNORE_REC *rec);
void ignore_update_rec(IGNORE_REC *rec);

void ignore_init(void);
void ignore_deinit(void);

#endif
