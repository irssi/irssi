#include "common.h"

#define MODULE_NAME "irc/notifylist"

#define ISON_EVENT "event 303"

typedef struct {
	char *nick;
	char *user, *host, *realname, *awaymsg;
	int idle_time;

	int host_ok:1; /* host matches the one in notifylist = this is the right person*/
	int away_ok:1; /* not away, or we don't care about it */
	int idle_ok:1; /* idle time is low enough, or we don't care about it */

	int away:1; /* nick is away */
	int join_announced:1; /* join to IRC has been announced */
	int idle_changed:1; /* idle time is lower than in last check */

	time_t last_whois;
} NOTIFY_NICK_REC;

typedef struct {
	GSList *notify_users; /* NOTIFY_NICK_REC's of notifylist people who are in IRC */
	GSList *ison_tempusers; /* Temporary list for saving /ISON events.. */
} MODULE_SERVER_REC;

#include "irc-server.h"

NOTIFY_NICK_REC *notify_nick_create(IRC_SERVER_REC *server, const char *nick);
void notify_nick_destroy(NOTIFY_NICK_REC *rec);
NOTIFY_NICK_REC *notify_nick_find(IRC_SERVER_REC *server, const char *nick);

void notifylist_left(IRC_SERVER_REC *server, NOTIFY_NICK_REC *rec);
void notifylist_destroy_all(void);

void notifylist_commands_init(void);
void notifylist_commands_deinit(void);

void notifylist_whois_init(void);
void notifylist_whois_deinit(void);

void notifylist_ison_init(void);
void notifylist_ison_deinit(void);
