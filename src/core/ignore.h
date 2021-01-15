#ifndef IRSSI_CORE_IGNORE_H
#define IRSSI_CORE_IGNORE_H

#include <irssi/src/core/iregex.h>

typedef struct _IGNORE_REC IGNORE_REC;

struct _IGNORE_REC {
	int level; /* ignore these levels */
	char *mask; /* nick mask */
	char *servertag; /* this is for autoignoring */
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
	IGNORE_FIND_NOACT = 0x02,     /* Exclude the targets with NOACT level */
	IGNORE_FIND_HIDDEN = 0x04,    /* Exclude the targets with HIDDEN level */
	IGNORE_FIND_NOHILIGHT = 0x08, /* Exclude the targets with NOHILIGHT level */
};

IGNORE_REC *ignore_find_full (const char *servertag, const char *mask, const char *pattern,
                char **channels, const int flags);

/* Convenience wrappers around ignore_find_full, for compatibility purpose */

IGNORE_REC *ignore_find(const char *servertag, const char *mask, char **channels);

void ignore_add_rec(IGNORE_REC *rec);
void ignore_update_rec(IGNORE_REC *rec);

void ignore_init(void);
void ignore_deinit(void);

#endif
