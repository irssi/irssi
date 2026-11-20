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

enum {
	PROXY_CAP_MESSAGE_TAGS = 1 << 0,
	PROXY_CAP_SERVER_TIME = 1 << 1,
	PROXY_CAP_MULTI_PREFIX = 1 << 2,
	PROXY_CAP_EXTENDED_JOIN = 1 << 3,
	PROXY_CAP_SETNAME = 1 << 4,
	PROXY_CAP_INVITE_NOTIFY = 1 << 5,
	PROXY_CAP_AWAY_NOTIFY = 1 << 6,
	PROXY_CAP_CHGHOST = 1 << 7,
	PROXY_CAP_ACCOUNT_NOTIFY = 1 << 8,
};

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
	unsigned int cap_negotiating : 1;
	unsigned int caps;
} CLIENT_REC;

#endif
