#include "common.h"

#define MODULE_NAME "proxy"

#include "network.h"
#include "line-split.h"
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
	LINEBUF_REC *buffer;

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

extern GSList *proxy_listens;
extern GSList *proxy_clients;

void proxy_listen_init(void);
void proxy_listen_deinit(void);

void proxy_settings_init(void);

void proxy_dump_data(CLIENT_REC *client);
void proxy_client_reset_nick(CLIENT_REC *client);

void proxy_outdata(CLIENT_REC *client, const char *data, ...);
void proxy_outdata_all(IRC_SERVER_REC *server, const char *data, ...);
void proxy_outserver(CLIENT_REC *client, const char *data, ...);
void proxy_outserver_all(IRC_SERVER_REC *server, const char *data, ...);
void proxy_outserver_all_except(CLIENT_REC *client, const char *data, ...);
