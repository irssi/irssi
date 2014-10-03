#ifndef H_IRSSI_SRC_CORE_PROXY_H
#define H_IRSSI_SRC_CORE_PROXY_H

#include <glib.h>
#include <stdint.h>

/* helper structure for the send_string*() functions of the network_proxy
 * class */
struct network_proxy_send_string_info {
	const char *host; /* hostname of the IRC server */
	uint16_t port; /* portnumber of the IRC server */

	/* function which is used to send string; usually irc_send_cmd_now() */
	void (*func)(void *obj, const char *);

	/* object for func */
	void *obj;
};

struct network_proxy {
	/* destroys the network_proxy structure which must not be used anymore
	 * after; this memberfunction is mandatory */
	void (*destroy)(struct network_proxy *);

	/* connects through the proxy; this memberfunction is mandatory
	 *
	 * \arg hint_ip   the asynchronously resolved ip of the proxy; when
	 *                NULL, method will resolve it itself
	 * \arg address   the hostname where proxy shall connect to
	 * \arg port      port address where proxy shall connect to
	 */
	GIOChannel *(*connect)(const struct *network_proxy, const IPADDR *hint_ip,
			       const char *address, int port);

	/* clones the given network_proxy object; this memberfunction is
	 * mandatory */
	struct network_proxy *(*clone)(const struct *network_proxy);


	/* sends a string after connection has been established but before IRC
	 * authentication begins; this memberfunction is optional
	 */
	void (*send_string)(const struct *network_proxy,
			    const struct *network_proxy_send_string_info);

	/* sends a string after connection IRC authentication suceeded; this
	 * memberfunction is optional
	 */
	void (*send_string_after)(const struct *network_proxy,
				  const struct *network_proxy_send_string_info);

	/* hostname of proxy host */
	const char *host;

	/* portnumber of proxy */
	int port;
};

/* factory method to create a proxy object based upon value of 'type' */
struct network_proxy *network_proxy_create(const char *type);

#endif
