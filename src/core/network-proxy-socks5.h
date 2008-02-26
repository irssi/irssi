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

#ifndef H_IRSSI_SRC_CORE_PROXY_SOCKS5_H
#define H_IRSSI_SRC_CORE_PROXY_SOCKS5_H

#include "network-proxy.h"

struct _network_proxy_socks5 {
	struct network_proxy	proxy;

	char const		*username;
	char const		*password;
};

struct network_proxy *		_network_proxy_socks5_create(void);

#endif	/* H_IRSSI_SRC_CORE_PROXY_SOCKS5_H */
