#ifndef H_IRSSI_SRC_CORE_PROXY_HTTP_H
#define H_IRSSI_SRC_CORE_PROXY_HTTP_H

#include "network-proxy.h"

struct _network_proxy_http {
	struct network_proxy proxy;
	const char *password;
};

struct network_proxy *_network_proxy_http_create(void);

#endif
