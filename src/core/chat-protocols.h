#ifndef __CHAT_PROTOCOLS_H
#define __CHAT_PROTOCOLS_H

#define PROTO_CHECK_CAST(object, cast, type_field, id) \
	((cast *) chat_protocol_check_cast(object, \
				offsetof(cast, type_field), id))
void *chat_protocol_check_cast(void *object, int type_pos, const char *id);

/* Register new chat protocol. */
void chat_protocol_register(const char *name,
			    const char *fullname,
			    const char *chatnet);

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name);

/* Return the ID for the specified chat protocol. */
int chat_protocol_lookup(const char *name);
/* Return the name for the specified chat protocol ID. */
const char *chat_protocol_get_name(int id);
/* Return the full name for the specified chat protocol ID. */
const char *chat_protocol_get_fullname(int id);
/* Return the chatnet identifier name for the specified chat protocol ID. */
const char *chat_protocol_get_chatnet(int id);

void chat_protocols_init(void);
void chat_protocols_deinit(void);

#endif
