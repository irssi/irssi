#ifndef __PERL_COMMON_H
#define __PERL_COMMON_H

#define new_pv(a) \
	(newSVpv((a) == NULL ? "" : (a), (a) == NULL ? 0 : strlen(a)))

extern GHashTable *perl_stashes;

HV *irssi_get_stash_item(int type, int chat_type);

#define irssi_get_stash(item) \
	irssi_get_stash_item((item)->type, (item)->chat_type)

#define irssi_add_stash(type, chat_type, stash) \
	g_hash_table_insert(perl_stashes, GINT_TO_POINTER(type | \
		(chat_type << 24)), g_strdup(stash))

void perl_common_init(void);
void perl_common_deinit(void);

#endif
