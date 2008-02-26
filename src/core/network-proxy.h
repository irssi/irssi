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

#ifndef H_IRSSI_SRC_CORE_PROXY_H
#define H_IRSSI_SRC_CORE_PROXY_H

#include <glib.h>
#include <stdint.h>

/* helper structure for the send_string*() functions of the network_proxy
 * class */
struct network_proxy_send_string_info
{
	char const		*host;	/* hostname of the IRC server */
	uint16_t		port;	/* portnumber of the IRC server */

	/* function which is used to send string; usually irc_send_cmd_now() */
	void			(*func)(void *obj, char const *);

	/* object for func */
	void			*obj;
};

struct network_proxy {
	/* destroys the network_proxy structure which must not be used anymore
	 * after; this memberfunction is mandatory */
	void			(*destroy)(struct network_proxy *);

	/* connects through the proxy; this memberfunction is mandatory
	 *
	 * \arg hint_ip   the asynchronously resolved ip of the proxy; when
	 *                NULL, method will resolve it itself
	 * \arg address   the hostname where proxy shall connect to
	 * \arg port      port address where proxy shall connect to
	 */
	GIOChannel *		(*connect)(struct network_proxy const *, IPADDR const *hint_ip,
					   char const *address, int port);

	/* clones the given network_proxy object; this memberfunction is
	 * mandatory */
	struct network_proxy *	(*clone)(struct network_proxy const *);


	/* sends a string after connection has been established but before IRC
	 * authentication begins; this memberfunction is optional
	 */
	void			(*send_string)(struct network_proxy const *,
					       struct network_proxy_send_string_info const *);

	/* sends a string after connection IRC authentication suceeded; this
	 * memberfunction is optional
	 */
	void			(*send_string_after)(struct network_proxy const *,
						     struct network_proxy_send_string_info const *);


	/* hostname of proxy host */
	char const		*host;

	/* portnumber of proxy */
	int			port;
};

/* factory method to create a proxy object based upon value of 'type' */
struct network_proxy *		network_proxy_create(char const *type);


#endif	/* H_IRSSI_SRC_CORE_PROXY_H */
