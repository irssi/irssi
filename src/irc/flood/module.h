#include "common.h"
#include "irc.h"

typedef struct {
	/* Flood protection */
	GHashTable *floodlist;

	/* Auto ignore list */
	GSList *ignorelist;
	time_t ignore_lastcheck;
} MODULE_SERVER_REC;

#define MODULE_NAME "irc/flood"
