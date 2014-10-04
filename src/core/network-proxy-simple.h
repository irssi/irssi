#ifndef H_IRSSI_SRC_CORE_PROXY_SIMPLE_H
#define H_IRSSI_SRC_CORE_PROXY_SIMPLE_H

#include "network-proxy.h"

struct _network_proxy_simple {
	struct network_proxy proxy;

	char *string_after;
	char *string;
	char *password;
};

struct network_proxy *_network_proxy_simple_create(void);

#endif
