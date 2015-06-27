#ifndef PROXY_H
#define PROXY_H

#include "common.h"

#include "network.h"
#include "irc.h"
#include "irc-servers.h"

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
	int port;
	char *ircnet;

	int tag;
	GIOChannel *handle;

	GSList *clients;
	unsigned int use_ssl;
	SSL_CTX *ssl_ctx;
	SSL_METHOD *ssl_method;
} LISTEN_REC;

typedef struct {
	char *nick, *host;
	int port;
	NET_SENDBUF_REC *handle;
	int recv_tag;
	char *proxy_address;
	LISTEN_REC *listen;
	IRC_SERVER_REC *server;
	unsigned int pass_sent:1;
	unsigned int user_sent:1;
	unsigned int connected:1;
	unsigned int want_ctcp:1;
	SSL *ssl;
} CLIENT_REC;

#endif
