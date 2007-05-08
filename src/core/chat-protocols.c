/*
 chat-protocol.c : irssi

    Copyright (C) 2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "modules.h"
#include "signals.h"
#include "chat-protocols.h"

#include "chatnets.h"
#include "servers.h"
#include "servers-setup.h"
#include "channels-setup.h"

GSList *chat_protocols;

static CHAT_PROTOCOL_REC *default_proto;

void *chat_protocol_check_cast(void *object, int type_pos, const char *id)
{
	return object == NULL ||
		chat_protocol_lookup(id) !=
		G_STRUCT_MEMBER(int, object, type_pos) ? NULL : object;
}

/* Return the ID for the specified chat protocol. */
int chat_protocol_lookup(const char *name)
{
	CHAT_PROTOCOL_REC *rec;

	g_return_val_if_fail(name != NULL, -1);

	rec = chat_protocol_find(name);
	return rec == NULL ? -1 : rec->id;
}

CHAT_PROTOCOL_REC *chat_protocol_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = chat_protocols; tmp != NULL; tmp = tmp->next) {
		CHAT_PROTOCOL_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

CHAT_PROTOCOL_REC *chat_protocol_find_id(int id)
{
	GSList *tmp;

	g_return_val_if_fail(id > 0, NULL);

	for (tmp = chat_protocols; tmp != NULL; tmp = tmp->next) {
		CHAT_PROTOCOL_REC *rec = tmp->data;

		if (rec->id == id)
			return rec;
	}

	return NULL;
}

CHAT_PROTOCOL_REC *chat_protocol_find_net(GHashTable *optlist)
{
	GSList *tmp;

	g_return_val_if_fail(optlist != NULL, NULL);

	for (tmp = chat_protocols; tmp != NULL; tmp = tmp->next) {
		CHAT_PROTOCOL_REC *rec = tmp->data;

		if (rec->chatnet != NULL &&
		    g_hash_table_lookup(optlist, rec->chatnet) != NULL)
                        return rec;
	}

	return NULL;
}

/* Register new chat protocol. */
CHAT_PROTOCOL_REC *chat_protocol_register(CHAT_PROTOCOL_REC *rec)
{
	CHAT_PROTOCOL_REC *newrec;
        int created;

	g_return_val_if_fail(rec != NULL, NULL);

	newrec = chat_protocol_find(rec->name);
        created = newrec == NULL;
	if (newrec == NULL) {
		newrec = g_new0(CHAT_PROTOCOL_REC, 1);
		chat_protocols = g_slist_append(chat_protocols, newrec);
	} else {
		/* updating existing protocol */
                g_free(newrec->name);
	}

	memcpy(newrec, rec, sizeof(CHAT_PROTOCOL_REC));
	newrec->id = module_get_uniq_id_str("PROTOCOL", rec->name);
	newrec->name = g_strdup(rec->name);

	if (default_proto == NULL)
                chat_protocol_set_default(newrec);

        if (created)
		signal_emit("chat protocol created", 1, newrec);
        else
		signal_emit("chat protocol updated", 1, newrec);
        return newrec;
}

static void chat_protocol_destroy(CHAT_PROTOCOL_REC *rec)
{
	g_return_if_fail(rec != NULL);

	chat_protocols = g_slist_remove(chat_protocols, rec);

	if (default_proto == rec) {
		chat_protocol_set_default(chat_protocols == NULL ? NULL :
					  chat_protocols->data);
	}

	signal_emit("chat protocol destroyed", 1, rec);

	g_free(rec->name);
	g_free(rec);
}

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name)
{
	CHAT_PROTOCOL_REC *rec;

	g_return_if_fail(name != NULL);

	rec = chat_protocol_find(name);
	if (rec != NULL) {
		chat_protocol_destroy(rec);

		/* there might still be references to this chat protocol -
		   recreate it as a dummy protocol */
		chat_protocol_get_unknown(name);
	}
}

/* Default chat protocol to use */
void chat_protocol_set_default(CHAT_PROTOCOL_REC *rec)
{
        default_proto = rec;
}

CHAT_PROTOCOL_REC *chat_protocol_get_default(void)
{
        return default_proto;
}

static CHATNET_REC *create_chatnet(void)
{
        return g_new0(CHATNET_REC, 1);
}

static SERVER_SETUP_REC *create_server_setup(void)
{
        return g_new0(SERVER_SETUP_REC, 1);
}

static CHANNEL_SETUP_REC *create_channel_setup(void)
{
        return g_new0(CHANNEL_SETUP_REC, 1);
}

static SERVER_CONNECT_REC *create_server_connect(void)
{
        return g_new0(SERVER_CONNECT_REC, 1);
}

static void destroy_server_connect(SERVER_CONNECT_REC *conn)
{
}

/* Return "unknown chat protocol" record. Used when protocol name is
   specified but it isn't registered yet. */
CHAT_PROTOCOL_REC *chat_protocol_get_unknown(const char *name)
{
	CHAT_PROTOCOL_REC *rec, *newrec;

	g_return_val_if_fail(name != NULL, NULL);

        rec = chat_protocol_find(name);
	if (rec != NULL)
                return rec;

	rec = g_new0(CHAT_PROTOCOL_REC, 1);
        rec->not_initialized = TRUE;
	rec->name = (char *) name;
	rec->create_chatnet = create_chatnet;
        rec->create_server_setup = create_server_setup;
        rec->create_channel_setup = create_channel_setup;
	rec->create_server_connect = create_server_connect;
	rec->destroy_server_connect = destroy_server_connect;

	newrec = chat_protocol_register(rec);
	g_free(rec);
        return newrec;
}

void chat_protocols_init(void)
{
	default_proto = NULL;
	chat_protocols = NULL;
}

void chat_protocols_deinit(void)
{
	while (chat_protocols != NULL)
                chat_protocol_destroy(chat_protocols->data);
}
