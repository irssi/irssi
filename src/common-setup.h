#ifndef __COMMON_SETUP_H
#define __COMMON_SETUP_H

#include "irc-base/network.h"
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
extern GSList *aliases, *ignores, *completions, *notifies, *hilights, *replaces, *popups;

/* servers */
typedef struct {
	char *server;
	int port;

	char *ircnet;
	char *password;
	int autoconnect;
	int cmd_queue_speed; /* override the default if > 0 */

        char *own_address; /* address to use when connecting this server */
	IPADDR own_ip; /* resolved own_address or full of zeros */

	time_t last_connect; /* to avoid reconnecting too fast.. */
	int last_failed; /* if last connection attempt failed */
} SETUP_SERVER_REC;

typedef struct {
	char *name;

	char *nick;
	char *username;
	char *realname;

	/* max. number of kicks/msgs/mode changes per command */
	int max_kicks, max_msgs, max_modes;
} IRCNET_REC;

extern GSList *setupservers; /* list of local servers */
extern GSList *ircnets; /* list of available ircnets */

/* channels */
typedef struct {
    int autojoin;

    char *name;
    char *ircnet;
    char *password;

    char *botmasks;
    char *autosendcmd;

    char *background;
    char *font;
} SETUP_CHANNEL_REC;

extern GSList *setupchannels;

extern gboolean readonly;
extern IPADDR source_host_ip; /* Resolved address */
extern gboolean source_host_ok; /* Use source_host_ip .. */

#endif
