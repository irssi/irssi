#ifndef __COMMON_SETUP_H
#define __COMMON_SETUP_H

#define LOG_FILE_CREATE_MODE 0644

/* wait for half an hour before trying to reconnect to host where last
   connection failed */
#define FAILED_RECONNECT_WAIT (60*30)

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

/* How long to keep netsplits in memory (seconds) */
#define NETSPLIT_MAX_REMEMBER (60*30)

#endif
