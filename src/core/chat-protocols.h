#ifndef __CHAT_PROTOCOLS_H
#define __CHAT_PROTOCOLS_H

struct _CHAT_PROTOCOL_REC {
	int id;

	unsigned int not_initialized:1;
	unsigned int case_insensitive:1;

	char *name;
	char *fullname;
	char *chatnet;

        CHATNET_REC *(*create_chatnet) (void);
	SERVER_SETUP_REC *(*create_server_setup) (void);
        CHANNEL_SETUP_REC *(*create_channel_setup) (void);
	SERVER_CONNECT_REC *(*create_server_connect) (void);
        void (*destroy_server_connect) (SERVER_CONNECT_REC *);

        SERVER_REC *(*server_init_connect) (SERVER_CONNECT_REC *);
        void (*server_connect) (SERVER_REC *);
	CHANNEL_REC *(*channel_create) (SERVER_REC *, const char *,
					const char *, int);
        QUERY_REC *(*query_create) (const char *, const char *, int);
};

extern GSList *chat_protocols;

#define PROTO_CHECK_CAST(object, cast, type_field, id) \
	((cast *) chat_protocol_check_cast(object, \
				offsetof(cast, type_field), id))
void *chat_protocol_check_cast(void *object, int type_pos, const char *id);

#define CHAT_PROTOCOL(object) \
	((object) == NULL ? chat_protocol_get_default() : \
	chat_protocol_find_id((object)->chat_type))

/* Register new chat protocol. */
CHAT_PROTOCOL_REC *chat_protocol_register(CHAT_PROTOCOL_REC *rec);

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name);

/* Find functions */
int chat_protocol_lookup(const char *name);
CHAT_PROTOCOL_REC *chat_protocol_find(const char *name);
CHAT_PROTOCOL_REC *chat_protocol_find_id(int id);
CHAT_PROTOCOL_REC *chat_protocol_find_net(GHashTable *optlist);

/* Default chat protocol to use */
void chat_protocol_set_default(CHAT_PROTOCOL_REC *rec);
CHAT_PROTOCOL_REC *chat_protocol_get_default(void);

/* Return "unknown chat protocol" record. Used when protocol name is
   specified but it isn't registered yet. */
CHAT_PROTOCOL_REC *chat_protocol_get_unknown(const char *name);

void chat_protocols_init(void);
void chat_protocols_deinit(void);

#endif
