#ifndef __BOT_H
#define __BOT_H

typedef struct
{
    PLUGIN_REC *plugin;
    gboolean loaded;

    GHashTable *users;
    GSList *botnets;

    gchar *nick;
    gint rank;

    time_t last_write;
}
PLUGIN_DATA;

void plugin_bot_events(PLUGIN_REC *plugin);

#include "botnet.h"
#include "users.h"

#define MODULE_NAME "bot"

#endif
