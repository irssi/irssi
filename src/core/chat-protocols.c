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
#include "signals.h"
#include "chat-protocols.h"

static int id_counter;
GSList *chat_protocols;

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

/* Register new chat protocol. */
void chat_protocol_register(CHAT_PROTOCOL_REC *rec)
{
	g_return_if_fail(rec != NULL);

	if (chat_protocol_find(rec->name) != NULL)
		return;

	rec->id = ++id_counter;
	chat_protocols = g_slist_append(chat_protocols, rec);

	signal_emit("chat protocol created", 1, rec);
}

static void chat_protocol_destroy(CHAT_PROTOCOL_REC *rec)
{
	g_return_if_fail(rec != NULL);

	chat_protocols = g_slist_remove(chat_protocols, rec);
	signal_emit("chat protocol destroyed", 1, rec);
	g_free(rec);
}

/* Unregister chat protocol. */
void chat_protocol_unregister(const char *name)
{
	CHAT_PROTOCOL_REC *rec;

	g_return_if_fail(name != NULL);

	rec = chat_protocol_find(name);
	if (rec != NULL) chat_protocol_destroy(rec);
}

void chat_protocols_init(void)
{
	id_counter = 0;
	chat_protocols = NULL;
}

void chat_protocols_deinit(void)
{
	while (chat_protocols != NULL)
                chat_protocol_destroy(chat_protocols->data);
}
