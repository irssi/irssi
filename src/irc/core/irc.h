#ifndef __IRC_H
#define __IRC_H

#include "irc-servers.h"

/* From ircd 2.9.5:
     none    I line with ident
     ^       I line with OTHER type ident
     ~       I line, no ident
     +       i line with ident
     =       i line with OTHER type ident
     -       i line, no ident
*/
#define ishostflag(a) \
	((a) == '^' || (a) == '~' || \
	(a) == '+' || (a) == '=' || (a) == '-')

#define isnickflag(a) \
	((a) == '@' || (a) == '+' || (a) == '%' || /* op / voice / half-op */ \
	(a) == '-' || (a) == '~') /* no idea, just copied from somewhere.. */

#define ischannel(a) \
	((a) == '#' || /* normal */ \
	(a) == '&' || /* local */ \
	(a) == '!' || /* secure */ \
	(a) == '+') /* modeless */

#define IS_IRC_ITEM(rec) (IS_IRC_CHANNEL(rec) || IS_IRC_QUERY(rec))

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

#include "commands.h" /* contains the generic PARAM_FLAG_xxx defines */

/* IRC specific: optional channel in first argument */
#define PARAM_FLAG_OPTCHAN 0x10000000

/* Get count parameters from data */
char *event_get_param(char **data);
char *event_get_params(const char *data, int count, ...);

void irc_irc_init(void);
void irc_irc_deinit(void);

#endif
