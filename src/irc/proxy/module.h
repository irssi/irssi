#include <irssip/src/common.h>

#define MODULE_NAME "proxy"

#include <irssip/src/core/network.h>
#include <irssip/src/irc/core/irc.h>
#include <irssip/src/irc/core/irc-servers.h>

#include <irssip/src/irc/proxy/proxy.h>

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
