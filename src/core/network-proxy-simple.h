#ifndef H_IRSSI_SRC_CORE_PROXY_SIMPLE_H
#define H_IRSSI_SRC_CORE_PROXY_SIMPLE_H

#include "network-proxy.h"

struct network_proxy_simple {
	char *string_after;
	char *string;
	char *password;
};

struct network_proxy *network_proxy_simple_create(void);

#endif
