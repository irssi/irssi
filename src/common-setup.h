#ifndef __COMMON_SETUP_H
#define __COMMON_SETUP_H

#include "settings/settings-public.h"

#define LOG_FILE_CREATE_MODE 0644
#define CMD_CHAR '/'

/* How often to check if there's anyone to be unignored in autoignore list */
#define AUTOIGNORE_TIMECHECK 10000

/* How often to check if there's anyone to be unbanned in knockout list */
#define KNOCKOUT_TIMECHECK 10000

/* How often to check users in notify list */
#define NOTIFY_TIMECHECK 30000

/* How often to check for gone status of nick */
#define MAX_GONE_REFRESH_TIME 300

/* Maximum time to wait for more JOINs before sending massjoin signal */
#define MAX_MASSJOIN_WAIT 5000

/* lists */
extern GList *aliases, *ignores, *completions, *notifies, *hilights, *replaces, *popups;

/* servers */
typedef struct
{
    gchar *server;
    gchar *ircnet;
    gchar *password;
    gint port;
    gboolean autoconnect;
    gint cmd_queue_speed; /* override the default if > 0 */
    time_t last_connect; /* to avoid reconnecting too fast.. */
}
SETUP_SERVER_REC;

typedef struct
{
    gchar *name;
    gchar *nick;
    gchar *username;
    gchar *realname;
    gint max_kicks, max_msgs, max_modes; /* max. number of kicks/msgs/mode changes per command */
}
IRCNET_REC;

extern GList *setupservers; /* list of local servers */
extern GList *ircnets; /* list of available ircnets */

extern IPADDR source_host_ip; /* Resolved address */
extern gboolean source_host_ok; /* Use source_host_ip .. */

/* channels */
typedef struct
{
    gboolean autojoin;
    gchar *name;
    gchar *ircnet;
    gchar *password;

    gchar *botmasks;
    gchar *autosendcmd;

    gchar *background;
    gchar *font;
}
SETUP_CHANNEL_REC;

extern GList *setupchannels;

extern gboolean readonly;

#endif
