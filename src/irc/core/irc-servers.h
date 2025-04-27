#ifndef IRSSI_IRC_CORE_IRC_SERVERS_H
#define IRSSI_IRC_CORE_IRC_SERVERS_H

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/irc/core/scram.h>

/*
 * 63 is the maximum hostname length defined by the protocol.  10 is a common
 * username limit on many networks.  1 is for the `@'.
 */
#define MAX_USERHOST_LEN (63 + 10 + 1)
#define MAX_IRC_MESSAGE_LEN (512 - 2) /* (2 bytes for CR+LF) */
#define MAX_IRC_TAGS_LEN (8191 - 2) /* (2 bytes for `@' and SPACE) */
#define MAX_IRC_USER_TAGS_LEN 4094

#define CAP_LS_VERSION "302"
#define CAP_MESSAGE_TAGS "message-tags"
#define CAP_SASL "sasl"
#define CAP_MULTI_PREFIX "multi-prefix"
#define CAP_EXTENDED_JOIN "extended-join"
#define CAP_SETNAME "setname"
#define CAP_INVITE_NOTIFY "invite-notify"
#define CAP_AWAY_NOTIFY "away-notify"
#define CAP_CHGHOST "chghost"
#define CAP_ACCOUNT_NOTIFY "account-notify"
#define CAP_SELF_MESSAGE "znc.in/self-message"
#define CAP_SERVER_TIME "server-time"
#define CAP_STARTTLS "tls"

/* returns IRC_SERVER_REC if it's IRC server, NULL if it isn't */
#define IRC_SERVER(server) \
	PROTO_CHECK_CAST(SERVER(server), IRC_SERVER_REC, chat_type, "IRC")

#define IRC_SERVER_CONNECT(conn) \
	PROTO_CHECK_CAST(SERVER_CONNECT(conn), IRC_SERVER_CONNECT_REC, \
			 chat_type, "IRC")

#define IS_IRC_SERVER(server) \
	(IRC_SERVER(server) ? TRUE : FALSE)

#define IS_IRC_SERVER_CONNECT(conn) \
	(IRC_SERVER_CONNECT(conn) ? TRUE : FALSE)

/* all strings should be either NULL or dynamically allocated */
/* address and nick are mandatory, rest are optional */
struct _IRC_SERVER_CONNECT_REC {
#include <irssi/src/core/server-connect-rec.h>

	char *usermode;
	char *alternate_nick;

	int sasl_mechanism;
	char *sasl_username;
	char *sasl_password;
	SCRAM_SESSION_REC *scram_session;

	int max_cmds_at_once;
	int cmd_queue_speed;
	int max_query_chans;

	int max_kicks, max_msgs, max_modes, max_whois;
	unsigned int disallow_starttls : 1;
	unsigned int starttls : 1;
	unsigned int no_cap : 1;
};

#define STRUCT_SERVER_CONNECT_REC IRC_SERVER_CONNECT_REC
struct _IRC_SERVER_REC {
#include <irssi/src/core/server-rec.h>

	int max_message_len; /* Maximum message length, default = 510 = 512 - 2 (for CR+LF) */

	/* For deciding if event should be redirected */
	GSList *redirects;
        GSList *redirect_queue; /* should be updated from redirect_next each time cmdqueue is updated */
        REDIRECT_REC *redirect_next;
	GSList *redirect_active; /* redirects start event has been received for, must have unique prefix */

        char *last_nick; /* last /NICK, kept even if it resulted as not valid change */

	char *real_address; /* address the irc server gives */
	char *usermode; /* The whole mode string .. */
        char *wanted_usermode; /* The usermode we want to use, doesn't include the modes given us by the server (eg. +r) */
	char *userhost; /* /USERHOST <nick> - set when joined to first channel */
	int channels_formed; /* channels formed in irc network */

	unsigned int whois_found:1; /* Did WHOIS return any entries? */
	unsigned int whowas_found:1; /* Did WHOWAS return any entries? */

	unsigned int emode_known:1; /* Server understands ban exceptions and invite lists */
	unsigned int no_multi_mode:1; /* Server doesn't understand MODE #chan1,#chan2,... */
	unsigned int no_multi_who:1; /* Server doesn't understand WHO #chan1,#chan2,... */
	unsigned int one_endofwho:1; /* /WHO #a,#b,.. replies only with one End of WHO message */
	unsigned int disable_lag:1; /* Disable lag detection (PING command doesn't exist) */
	unsigned int nick_collision:1; /* We're just now being killed because of nick collision */
	unsigned int motd_got:1; /* We've received MOTD */
	unsigned int isupport_sent:1; /* Server has sent us an isupport reply */
	unsigned int cap_complete:1; /* We've done the initial CAP negotiation */
	unsigned int cap_in_multiline:1; /* We're waiting for the multiline response to end */
	unsigned int sasl_success:1; /* Did we authenticate successfully ? */

	int max_kicks_in_cmd; /* max. number of people to kick with one /KICK command */
	int max_modes_in_cmd; /* max. number of mode changes in one /MODE command */
	int max_whois_in_cmd; /* max. number of nicks in one /WHOIS command */
	int max_msgs_in_cmd; /* max. number of targets in one /MSG */

	GHashTable *cap_supported; /* A list of caps supported by the server */
	GSList *cap_active;    /* A list of caps active for this session */
	GSList *cap_queue;     /* A list of caps to request on connection */ 

	GString *sasl_buffer; /* Buffer used to reassemble a fragmented SASL payload */
	guint sasl_timeout;   /* Holds the source id of the running timeout */

	/* Command sending queue */
	int cmdcount; /* number of commands in `cmdqueue'. Can be more than
	                 there actually is, to make flood control remember
			 how many messages can be sent before starting the
			 flood control */
	int cmdlater; /* number of commands in queue to be sent later */
	GSList *cmdqueue; /* command, redirection, ... */
	gint64 wait_cmd; /* don't send anything to server before this */
	gint64 last_cmd; /* last time command was sent to server */

	int max_cmds_at_once; /* How many messages can be sent immediately before timeouting starts */
	int cmd_queue_speed; /* Timeout between sending commands */
	int max_query_chans; /* when syncing, max. number of channels to
				put in one MODE/WHO command */

	GSList *idles; /* Idle queue - send these commands to server
	                  if there's nothing else to do */

	GSList *ctcpqueue; /* CTCP flood protection - list of tags in idle queue */

	/* /knockout ban list */
	GSList *knockoutlist;

	GHashTable *splits; /* For keeping track of netsplits */
	GSList *split_servers; /* Servers that are currently in split */

	GSList *rejoin_channels; /* try to join to these channels after a while -
	                            channels go here if they're "temporarily unavailable"
				    because of netsplits */
	guint starttls_tag;      /* Holds the source id of the running timeout */
	struct _SERVER_QUERY_REC *chanqueries;

	GHashTable *isupport;
	struct modes_type modes[256]; /* Stores the modes sent by a server in an isupport reply */
	char prefix[256];

	int (*nick_comp_func)(const char *, const char *); /* Function for comparing nicknames on this server */
};

SERVER_REC *irc_server_init_connect(SERVER_CONNECT_REC *conn);
void irc_server_connect(SERVER_REC *server);

/* Purge server output, either all or for specified target */
void irc_server_purge_output(IRC_SERVER_REC *server, const char *target);

enum {
	REJOIN_CHANNELS_MODE_OFF = 0, /* */
	REJOIN_CHANNELS_MODE_ON,
	REJOIN_CHANNELS_MODE_AUTO
};

/* Return a string of all channels (and keys, if any have them) in server,
   like "#a,#b,#c,#d x,b_chan_key,x,x" or just "#e,#f,#g" */
char *irc_server_get_channels(IRC_SERVER_REC *server, int rejoin_channels_mode);

void irc_server_send_starttls(IRC_SERVER_REC *server);
/* INTERNAL: */
void irc_server_send_action(IRC_SERVER_REC *server, const char *target,
			    const char *data);
char **irc_server_split_action(IRC_SERVER_REC *server, const char *target,
			       const char *data);
void irc_server_send_away(IRC_SERVER_REC *server, const char *reason);
void irc_server_send_data(IRC_SERVER_REC *server, const char *data, int len);
void irc_server_send_and_redirect(IRC_SERVER_REC *server, GString *str, REDIRECT_REC *redirect);
void irc_server_init_isupport(IRC_SERVER_REC *server);

void irc_servers_start_cmd_timeout(void);

void irc_servers_init(void);
void irc_servers_deinit(void);

#endif
