#ifndef __CHAT_PROTOCOLS_H
#define __CHAT_PROTOCOLS_H

typedef struct {
	int id;

	char *name;
	char *fullname;
	char *chatnet;
} CHAT_PROTOCOL_REC;

extern GSList *chat_protocols;

#define PROTO_CHECK_CAST(object, cast, type_field, id) \
	((cast *) chat_protocol_check_cast(object, \
				offsetof(cast, type_field), id))
void *chat_protocol_check_cast(void *object, int type_pos, const char *id);

/* Register new chat protocol. */
void chat_protocol_register(CHAT_PROTOCOL_REC *rec);

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name);

/* Find functions */
int chat_protocol_lookup(const char *name);
CHAT_PROTOCOL_REC *chat_protocol_find(const char *name);
CHAT_PROTOCOL_REC *chat_protocol_find_id(int id);

void chat_protocols_init(void);
void chat_protocols_deinit(void);

#endif
