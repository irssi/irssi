#ifndef H_IRSSI_SRC_CORE_PROXY_SOCKS5_H
#define H_IRSSI_SRC_CORE_PROXY_SOCKS5_H

#include "network-proxy.h"

struct _network_proxy_socks5 {
	struct network_proxy proxy;

	char *username;
	char *password;
};

struct network_proxy *_network_proxy_socks5_create(void);

#endif
