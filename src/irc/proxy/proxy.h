#ifndef IRSSI_IRC_PROXY_PROXY_H
#define IRSSI_IRC_PROXY_PROXY_H

#include <irssi/src/common.h>

#include <irssi/src/core/network.h>
#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-servers.h>

typedef struct {
	int port;
	char *port_or_path;
	char *ircnet;

	int tag;
	GIOChannel *handle;

	GSList *clients;

} LISTEN_REC;

typedef struct {
	char *nick, *addr;
	NET_SENDBUF_REC *handle;
	int recv_tag;
	char *proxy_address;
	LISTEN_REC *listen;
	IRC_SERVER_REC *server;
	unsigned int pass_sent:1;
	unsigned int user_sent:1;
	unsigned int connected:1;
	unsigned int want_ctcp:1;
	unsigned int multiplex:1;
} CLIENT_REC;

#endif
