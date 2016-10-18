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

#ifndef __PROXY_H
#define __PROXY_H

#include "modules.h"

#define PROXY(proxy) \
	MODULE_CHECK_CAST(proxy, PROXY_REC, type, "PROXY")

#define IS_PROXY(proxy) \
	(PROXY(proxy) ? TRUE : FALSE)

struct _PROXY_REC {
#include "proxy-rec.h"
};

extern GSList *proxies;

/* Add a proxy to the proxy list. */
void proxy_create(PROXY_REC *proxy);

/* Remove a proxy from the proxy list. */
void proxy_remove(PROXY_REC *proxy);

/* Destroy the proxy structure without removing it from configs. */
void proxy_destroy(PROXY_REC *proxy);

/* Find a proxy by name. */
PROXY_REC *proxy_find(const char *name);

void proxy_init(void);
void proxy_deinit(void);

#endif

