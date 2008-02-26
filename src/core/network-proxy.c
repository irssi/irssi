/*	--*- c -*--
 * Copyright (C) 2008 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 and/or 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "module.h"

#include "network-proxy.h"
#include <string.h>
#include "network-proxy-simple.h"
#include "network-proxy-http.h"
#include "network-proxy-socks5.h"

struct network_proxy *
network_proxy_create(char const *type)
{
	if (type==NULL)
		return NULL;

	if (strcmp(type, "simple")==0 || type[0]=='\0')
		return _network_proxy_simple_create();

	if (strcmp(type, "http")==0)
		return _network_proxy_http_create();

	if (strcmp(type, "socks5")==0)
		return _network_proxy_socks5_create();

	g_error("unsupported proxy type '%s'", type);
	return NULL;
}
