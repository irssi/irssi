#ifndef PROXY_H
#define PROXY_H

#include "common.h"

#include "network.h"
#include "irc.h"
#include "irc-servers.h"

typedef struct {
	int port;
	char *ircnet;

	int tag;
	GIOChannel *handle;

	GSList *clients;
} LISTEN_REC;

typedef struct {
	char *nick, *host;
	NET_SENDBUF_REC *handle;
	int recv_tag;
	char *proxy_address;
	LISTEN_REC *listen;
	IRC_SERVER_REC *server;
	unsigned int pass_sent:1;
	unsigned int user_sent:1;
	unsigned int connected:1;
	unsigned int want_ctcp:1;
} CLIENT_REC;

#endif
