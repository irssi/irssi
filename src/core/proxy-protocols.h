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

#ifndef __PROXY_PROTOCOLS_H
#define __PROXY_PROTOCOLS_H

#include "modules.h"

struct _PROXY_PROTOCOL_REC {
	int id;
	char *name;
};

extern GSList *proxy_protocols;

/* Register new Proxy Protocol. */
PROXY_PROTOCOL_REC *proxy_protocol_register(PROXY_PROTOCOL_REC *rec);

/* Unregister Proxy Protocol. */
void proxy_protocol_unregister(const char *name);

/* Lookup Proxy Protocols. */
int proxy_protocol_lookup(const char *name);
PROXY_PROTOCOL_REC *proxy_protocol_find(const char *name);
PROXY_PROTOCOL_REC *proxy_protocol_find_id(int id);

void proxy_protocols_init(void);
void proxy_protocols_deinit(void);

#endif
