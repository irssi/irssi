#ifndef __IRC_H
#define __IRC_H

#include "modules.h"
#include "irc-server.h"

/* From ircd 2.9.5:
     none    I line with ident
     ^       I line with OTHER type ident
     ~       I line, no ident
     +       i line with ident
     =       i line with OTHER type ident
     -       i line, no ident
*/
#define ishostflag(a) ((a) == '^' || (a) == '~' || (a) == '+' || (a) == '=' || (a) == '-')
#define isnickflag(a) ((a) == '@' || (a) == '+' || (a) == '-' || (a) == '~')
#define ischannel(a) ((a) == '#' || (a) == '&' || (a) == '!' || (a) == '+')

/* values returned by module_category() */
enum {
	WI_IRC_CHANNEL,
	WI_IRC_QUERY
};

/* *MUST* have the same contents as WI_ITEM_REC in same order. */
typedef struct {
	int type;
	GHashTable *module_data;

	IRC_SERVER_REC *server;
	char *name;

	int new_data;
} WI_IRC_REC;

/* return TRUE if `item' is an IRC type. */
#define irc_item_check(item) \
	(item != NULL && module_find_id("IRC", ((WI_IRC_REC *) (item))->type) != -1)

/* return `item' type, or -1 if it's not IRC type. */
#define irc_item_get(item) \
	(item == NULL ? -1 : module_find_id("IRC", ((WI_IRC_REC *) (item))->type))

/* Return `item' if it's channel, NULL if it isn't. */
#define irc_item_channel(item) \
	(item != NULL && module_find_id("IRC", ((WI_IRC_REC *) (item))->type) == WI_IRC_CHANNEL ? \
	(void *) (item) : NULL)

/* Return `item' if it's query, NULL if it isn't. */
#define irc_item_query(item) \
	(item != NULL && module_find_id("IRC", ((WI_IRC_REC *) (item))->type) == WI_IRC_QUERY ? \
	(void *) (item) : NULL)

/* Return `item' if it's DCC chat, NULL if it isn't. */
#define irc_item_dcc_chat(item) \
	(item != NULL && module_find_id("IRC", ((WI_IRC_REC *) (item))->type) == WI_IRC_DCC_CHAT ? \
	(void *) (item) : NULL)

extern char *current_server_event; /* current server event being processed */

/* Send command to IRC server */
void irc_send_cmd(IRC_SERVER_REC *server, const char *cmd);
void irc_send_cmdv(IRC_SERVER_REC *server, const char *cmd, ...) G_GNUC_PRINTF (2, 3);
/* Send command to IRC server, split to multiple commands if necessary so
   that command will never have more target nicks than `max_nicks'. Nicks
   are separated with commas. (works with /msg, /kick, ...) */
void irc_send_cmd_split(IRC_SERVER_REC *server, const char *cmd,
			int nickarg, int max_nicks);
/* Send command to server immediately bypassing all flood protections
   and queues. */
void irc_send_cmd_now(IRC_SERVER_REC *server, const char *cmd);

/* Nick can be in format "servertag/nick" - Update `nick' to
   position "nick" and return "servertag" which you need to free */
char *irc_nick_get_server(char **nick);

#include "commands.h" /* contains the generic PARAM_FLAG_xxx defines */

/* IRC specific: optional channel in first argument */
#define PARAM_FLAG_OPTCHAN 0x10000000

/* Get count parameters from data */
char *event_get_param(char **data);
char *event_get_params(const char *data, int count, ...);

void irc_irc_init(void);
void irc_irc_deinit(void);

#endif
