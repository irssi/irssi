#ifndef __CHAT_PROTOCOLS_H
#define __CHAT_PROTOCOLS_H

typedef struct {
	char *name;
	char *fullname;
	char *chatnet;
} CHAT_PROTOCOL_REC;

#define PROTO_CHECK_CAST(object, cast, type_field, id) \
	((cast *) chat_protocol_check_cast(object, \
				offsetof(cast, type_field), id))
void *chat_protocol_check_cast(void *object, int type_pos, const char *id);

/* Register new chat protocol. */
void chat_protocol_register(CHAT_PROTOCOL_REC *rec);

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name);

/* Return the ID for the specified chat protocol. */
int chat_protocol_lookup(const char *name);
/* Return the record for the specified chat protocol ID. */
CHAT_PROTOCOL_REC *chat_protocol_get_rec(int id);

void chat_protocols_init(void);
void chat_protocols_deinit(void);

#endif
