#ifndef H_IRSSI_SRC_CORE_PROXY_SOCKS5_H
#define H_IRSSI_SRC_CORE_PROXY_SOCKS5_H

#include "network-proxy.h"

struct network_proxy_socks5 {
	char *username;
	char *password;
};

struct network_proxy *network_proxy_socks5_create(void);

#endif
