#ifndef __NICKMATCH_CACHE_H
#define __NICKMATCH_CACHE_H

typedef void (*NICKMATCH_REBUILD_FUNC) (GHashTable *list,
					CHANNEL_REC *channel, NICK_REC *nick);

typedef struct {
        GHashTable *nicks;
	NICKMATCH_REBUILD_FUNC func;
} NICKMATCH_REC;

NICKMATCH_REC *nickmatch_init(NICKMATCH_REBUILD_FUNC func);
void nickmatch_deinit(NICKMATCH_REC *rec);

/* Calls rebuild function for all nicks in all channels.
   This must be called soon after nickmatch_init(), before any nicklist
   signals get sent. */
void nickmatch_rebuild(NICKMATCH_REC *rec);

#define nickmatch_find(rec, nick) \
        g_hash_table_lookup((rec)->nicks, nick)

void nickmatch_cache_init(void);
void nickmatch_cache_deinit(void);

#endif
