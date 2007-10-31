#include "common.h"
#include "irc.h"

#define MODULE_NAME "irc/notifylist"

typedef struct {
	char *nick;
	char *user, *host, *realname, *awaymsg;

	unsigned int host_ok:1; /* host matches the one in notifylist = this is the right person*/
	unsigned int away_ok:1; /* not away, or we don't care about it */

	unsigned int away:1; /* nick is away */
	unsigned int join_announced:1; /* join to IRC has been announced */

	time_t last_whois;
} NOTIFY_NICK_REC;

typedef struct {
	int ison_count; /* number of ISON requests sent */

	GSList *notify_users; /* NOTIFY_NICK_REC's of notifylist people who are in IRC */
	GSList *ison_tempusers; /* Temporary list for saving /ISON events.. */
} MODULE_SERVER_REC;

#include "irc-servers.h"

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
