#ifndef __IRC_SERVERS_H
#define __IRC_SERVERS_H

#include "chat-protocols.h"
#include "servers.h"

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
typedef struct {
#include "server-connect-rec.h"

	char *usermode;
	char *alternate_nick;

	int max_cmds_at_once;
	int cmd_queue_speed;
	int max_query_chans;

	int max_kicks, max_msgs, max_modes, max_whois;
} IRC_SERVER_CONNECT_REC;

#define STRUCT_SERVER_CONNECT_REC IRC_SERVER_CONNECT_REC
typedef struct {
#include "server-rec.h"

	char *real_address; /* address the irc server gives */
	char *usermode; /* The whole mode string .. */
        char *userhost; /* /USERHOST <nick> - set when joined to first channel */
	int channels_formed; /* channels formed in irc network */

	unsigned int nick_changing:1; /* We've sent nick change command to server */
	unsigned int whois_coming:1; /* Mostly just to display away message right.. */
	unsigned int whois_found:1; /* Did WHOIS return any entries? */
	unsigned int whowas_found:1; /* Did WHOWAS return any entries? */

	unsigned int emode_known:1; /* Server understands ban exceptions and invite lists */
	unsigned int no_multi_mode:1; /* Server doesn't understand MODE #chan1,#chan2,... */
	unsigned int no_multi_who:1; /* Server doesn't understand WHO #chan1,#chan2,... */
	unsigned int one_endofwho:1; /* /WHO #a,#b,.. replies only with one End of WHO message */

	int max_kicks_in_cmd; /* max. number of people to kick with one /KICK command */
	int max_modes_in_cmd; /* max. number of mode changes in one /MODE command */
	int max_whois_in_cmd; /* max. number of nicks in one /WHOIS command */
	int max_msgs_in_cmd; /* max. number of targets in one /MSG */

	/* Command sending queue */
	int cmdcount; /* number of commands in `cmdqueue'. Can be more than
	                 there actually is, to make flood control remember
			 how many messages can be sent before starting the
			 flood control */
	GSList *cmdqueue;
	GTimeVal wait_cmd; /* don't send anything to server before this */
	GTimeVal last_cmd; /* last time command was sent to server */

	int max_cmds_at_once; /* How many messages can be sent immediately before timeouting starts */
	int cmd_queue_speed; /* Timeout between sending commands */
	int max_query_chans; /* when syncing, max. number of channels to
				put in one MODE/WHO command */

	GSList *idles; /* Idle queue - send these commands to server
	                  if there's nothing else to do */

	GSList *ctcpqueue; /* CTCP flood protection - list of tags in idle queue */

	/* /knockout ban list */
	GSList *knockoutlist;
	time_t knockout_lastcheck;

	GHashTable *splits; /* For keeping track of netsplits */
	GSList *split_servers; /* Servers that are currently in split */

	GSList *rejoin_channels; /* try to join to these channels after a while -
	                            channels go here if they're "temporarily unavailable"
				    because of netsplits */
	void *chanqueries;
} IRC_SERVER_REC;

IRC_SERVER_REC *irc_server_connect(IRC_SERVER_CONNECT_REC *conn);

/* Return a string of all channels (and keys, if any have them) in server,
   like "#a,#b,#c,#d x,b_chan_key,x,x" or just "#e,#f,#g" */
char *irc_server_get_channels(IRC_SERVER_REC *server);

void irc_servers_init(void);
void irc_servers_deinit(void);

#endif
