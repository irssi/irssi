#ifndef H_IRSSI_SRC_CORE_PROXY_HTTP_H
#define H_IRSSI_SRC_CORE_PROXY_HTTP_H

#include "network-proxy.h"

struct network_proxy_http {
	char *password;
};

struct network_proxy *network_proxy_http_create(void);

#endif
