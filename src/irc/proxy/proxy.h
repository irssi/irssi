#ifndef __PROXY_H
#define __PROXY_H


#include "module.h"
#include "../../core/modules.h"

#include "network.h"
#include <core/line-split.h>
#include <core/servers-redirect.h>
#include "commands.h"

typedef struct
{
    MODULE_REC *plugin;
    gboolean loaded;

    IPADDR ip;
    gint port;
    gchar *password;

    gint listen_tag;
    gint listen_handle;

    GSList *clients;
}
PLUGIN_DATA;

typedef struct
{
    LINEBUF_REC *buffer;

    gchar *nick;
    gint handle;
    gint tag;

    SERVER_REC *server;
    gboolean pass_sent;
    gboolean connected;
}
CLIENT_REC;

void plugin_proxy_setup_init(MODULE_REC *plugin);
void plugin_proxy_setup_deinit(MODULE_REC *plugin);

void plugin_proxy_listen_init();
void plugin_proxy_listen_deinit();

void proxy_settings_init(void);

void plugin_proxy_dump_data(CLIENT_REC *client);

/*  #define MODULE_NAME "proxy" */

#endif
