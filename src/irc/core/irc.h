#ifndef IRSSI_IRC_CORE_IRC_H
#define IRSSI_IRC_CORE_IRC_H

typedef struct _IRC_CHATNET_REC IRC_CHATNET_REC;
typedef struct _IRC_SERVER_CONNECT_REC IRC_SERVER_CONNECT_REC;
typedef struct _IRC_SERVER_REC IRC_SERVER_REC;
typedef struct _IRC_CHANNEL_REC IRC_CHANNEL_REC;
typedef struct _REDIRECT_REC REDIRECT_REC;

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

#define isnickflag(server, a) \
	(server->prefix[(int)(unsigned char) a] != '\0')

#define IS_IRC_ITEM(rec) (IS_IRC_CHANNEL(rec) || IS_IRC_QUERY(rec))
#define IRC_PROTOCOL (chat_protocol_lookup("IRC"))

extern char *current_server_event; /* current server event being processed */

enum {
	IRC_SEND_NOW, /* */
	IRC_SEND_NEXT,
	IRC_SEND_NORMAL,
	IRC_SEND_LATER
};

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
/* Send command to server putting it at the beginning of the queue of
    commands to send -- it will go out as soon as possible in accordance
    to the flood protection settings. */
void irc_send_cmd_first(IRC_SERVER_REC *server, const char *cmd);
/* Send command to server putting it at the end of the queue. */
void irc_send_cmd_later(IRC_SERVER_REC *server, const char *cmd);
/* The core of the irc_send_cmd* functions. If `raw' is TRUE, the `cmd'
   won't be checked at all if it's 512 bytes or not, or if it contains
   line feeds or not. Use with extreme caution! */
void irc_send_cmd_full(IRC_SERVER_REC *server, const char *cmd, int irc_send_when, int raw);

/* Extract a tag value from tags */
GHashTable *irc_parse_message_tags(const char *tags);

/* Get count parameters from data */
#include <irssi/src/core/commands.h>
char *event_get_param(char **data);
char *event_get_params(const char *data, int count, ...);

void irc_irc_init(void);
void irc_irc_deinit(void);

#endif
