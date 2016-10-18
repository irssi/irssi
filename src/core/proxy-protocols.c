/*
 * Copyright (c) 2015 Alexander Færøy <ahf@irssi.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "module.h"
#include "proxy-protocols.h"
#include "signals.h"

GSList *proxy_protocols;

static void proxy_protocol_destroy(PROXY_PROTOCOL_REC *rec)
{
	g_return_if_fail(rec != NULL);

	proxy_protocols = g_slist_remove(proxy_protocols, rec);

	signal_emit("proxy protocol destroyed", 1, rec);

	g_free(rec->name);
	g_free(rec);
}

/* Register new Proxy Protocol. */
PROXY_PROTOCOL_REC *proxy_protocol_register(PROXY_PROTOCOL_REC *rec)
{
	PROXY_PROTOCOL_REC *newrec;
	int created;

	g_return_val_if_fail(rec != NULL, NULL);

	newrec = proxy_protocol_find(rec->name);
	created = newrec == NULL;

	if (created) {
		newrec = g_new0(PROXY_PROTOCOL_REC, 1);
		proxy_protocols = g_slist_append(proxy_protocols, newrec);
	} else {
		g_free(newrec->name);
	}

	memcpy(newrec, rec, sizeof(PROXY_PROTOCOL_REC));

	newrec->id = module_get_uniq_id_str("PROXY PROTOCOL", rec->name);
	newrec->name = g_strdup(rec->name);

	if (created)
		signal_emit("proxy protocol created", 1, newrec);
	else
		signal_emit("proxy protocol updated", 1, newrec);

	return newrec;
}

/* Unregister Proxy Protocol. */
void proxy_protocol_unregister(const char *name)
{
	PROXY_PROTOCOL_REC *rec;

	g_return_if_fail(name != NULL);

	rec = proxy_protocol_find(name);

	if (rec != NULL)
		proxy_protocol_destroy(rec);
}

/* Lookup Proxy Protocols. */
int proxy_protocol_lookup(const char *name)
{
	PROXY_PROTOCOL_REC *rec;

	g_return_val_if_fail(name != NULL, -1);

	rec = proxy_protocol_find(name);

	return rec == NULL ? -1 : rec->id;
}

PROXY_PROTOCOL_REC *proxy_protocol_find(const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(name != NULL, NULL);

	for (tmp = proxy_protocols; tmp != NULL; tmp = tmp->next) {
		PROXY_PROTOCOL_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

PROXY_PROTOCOL_REC *proxy_protocol_find_id(int id)
{
	GSList *tmp;

	g_return_val_if_fail(id > 0, NULL);

	for (tmp = proxy_protocols; tmp != NULL; tmp = tmp->next) {
		PROXY_PROTOCOL_REC *rec = tmp->data;

		if (rec->id == id)
			return rec;
	}

	return NULL;
}

void proxy_protocols_init(void)
{
	proxy_protocols = NULL;
}

void proxy_protocols_deinit(void)
{
	while (proxy_protocols != NULL)
		proxy_protocol_destroy(proxy_protocols->data);
}
