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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "chat-protocols.h"

typedef struct {
	int id;
	CHAT_PROTOCOL_REC *rec;
} PROTOCOL_REC;

static int id_counter;
static GSList *protocols;

void *chat_protocol_check_cast(void *object, int type_pos, const char *id)
{
	return object == NULL ||
		chat_protocol_lookup(id) !=
		G_STRUCT_MEMBER(int, object, type_pos) ? NULL : object;
}

static PROTOCOL_REC *chat_protocol_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = protocols; tmp != NULL; tmp = tmp->next) {
		PROTOCOL_REC *rec = tmp->data;

		if (g_strcasecmp(rec->rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

static PROTOCOL_REC *chat_protocol_find_id(int id)
{
	GSList *tmp;

	g_return_val_if_fail(id > 0, NULL);

	for (tmp = protocols; tmp != NULL; tmp = tmp->next) {
		PROTOCOL_REC *rec = tmp->data;

		if (rec->id == id)
			return rec;
	}

	return NULL;
}

/* Register new chat protocol. */
void chat_protocol_register(CHAT_PROTOCOL_REC *rec)
{
	PROTOCOL_REC *proto;

	g_return_if_fail(rec != NULL);

	if (chat_protocol_find(rec->name) != NULL)
		return;

	proto = g_new0(PROTOCOL_REC, 1);
	proto->id = ++id_counter;
	proto->rec = rec;
	protocols = g_slist_append(protocols, proto);
}

static void chat_protocol_destroy(PROTOCOL_REC *rec)
{
	g_return_if_fail(rec != NULL);

	protocols = g_slist_remove(protocols, rec);
	g_free(rec->rec);
	g_free(rec);
}

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name)
{
	PROTOCOL_REC *rec;

	g_return_if_fail(name != NULL);

	rec = chat_protocol_find(name);
	if (rec != NULL) chat_protocol_destroy(rec);
}

/* Return the ID for the specified chat protocol. */
int chat_protocol_lookup(const char *name)
{
	PROTOCOL_REC *rec;

	g_return_val_if_fail(name != NULL, -1);

	rec = chat_protocol_find(name);
	return rec == NULL ? -1 : rec->id;
}

/* Return the record for the specified chat protocol ID. */
CHAT_PROTOCOL_REC *chat_protocol_get_rec(int id)
{
	PROTOCOL_REC *rec;

	g_return_val_if_fail(id > 0, NULL);

        rec = chat_protocol_find_id(id);
	return rec == NULL ? NULL : rec->rec;
}

void chat_protocols_init(void)
{
	id_counter = 0;
	protocols = NULL;
}

void chat_protocols_deinit(void)
{
	while (protocols != NULL)
                chat_protocol_destroy(protocols->data);
}
