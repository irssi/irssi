#ifndef __IRC_SERVER_H
#define __IRC_SERVER_H

#include "server.h"

enum {
	SERVER_TYPE_IRC
};

/* return if `server' doesn't point to IRC server record. */
#define irc_server_check(server) \
	((server) != NULL && module_find_id("IRC SERVER", (server)->type) != -1)

/* all strings should be either NULL or dynamically allocated */
/* address and nick are mandatory, rest are optional */
typedef struct {
        /* -- GENERIC SERVER_CONNECT_REC - don't change! -- */
	/* if we're connecting via proxy, or just NULLs */
	char *proxy;
	int proxy_port;
	char *proxy_string;

	/* server where we want to connect */
	char *address;
	int port;
	char *ircnet;

	IPADDR *own_ip;

        /* -- IRC specific - change if you wish -- */
	char *password;
	char *nick, *alternate_nick;
	char *username;
	char *realname;

	int max_cmds_at_once;
	int cmd_queue_speed;
	int max_kicks, max_msgs, max_modes, max_whois;

	/* when reconnecting, the old server status */
	int reconnection:1; /* we're trying to reconnect */
	char *channels;
	char *away_reason;
	char *usermode;
} IRC_SERVER_CONNECT_REC;

typedef struct {
        /* -- GENERIC SERVER_REC - don't change! -- */
	int type; /* server type */

	IRC_SERVER_CONNECT_REC *connrec;
	time_t connect_time; /* connection time */

	char *tag; /* tag name for addressing server */
	char *nick; /* current nick */

	int connected:1; /* connected to server */
	int connection_lost:1; /* Connection lost unintentionally */

	int handle; /* socket handle */
	int readtag; /* input tag */

	/* for net_connect_nonblock() */
	int connect_pipe[2];
	int connect_tag;
	int connect_pid;

	/* For deciding if event should be handled internally */
	GHashTable *eventtable; /* "event xxx" : GSList* of REDIRECT_RECs */
	GHashTable *eventgrouptable; /* event group : GSList* of REDIRECT_RECs */
	GHashTable *cmdtable; /* "command xxx" : REDIRECT_CMD_REC* */

	void *rawlog;
	void *buffer; /* receive buffer */
	GHashTable *module_data;

        /* -- IRC specific - change if you wish -- */
	char *real_address; /* address the irc server gives */
        char *version; /* server version - taken from 004 event */
	char *usermode; /* The whole mode string .. */
        char *userhost; /* /USERHOST <nick> - set when joined to first channel */
        char *last_invite; /* channel where you were last invited */
	char *away_reason;
	int usermode_away:1;
	int server_operator:1;

	int whois_coming:1; /* Mostly just to display away message right.. */

	int emode_known:1; /* Server understands ban exceptions and invite lists */
	int no_multi_mode:1; /* Server doesn't understand MODE #chan1,#chan2,... */
	int no_multi_who:1; /* Server doesn't understand WHO #chan1,#chan2,... */
	int one_endofwho:1; /* /WHO #a,#b,.. replies only with one End of WHO message */

	int max_kicks_in_cmd; /* max. number of people to kick with one /KICK command */
	int max_modes_in_cmd; /* max. number of mode changes in one /MODE command */
	int max_whois_in_cmd; /* max. number of nicks in one /WHOIS command */
	int max_msgs_in_cmd; /* max. number of targets in one /MSG */

	/* Command sending queue */
	int cmdcount; /* number of commands in `cmdqueue'. Can be more than
	                 there actually is, to make flood control remember
			 how many messages can be sent before starting the
			 flood control */
	int cmd_last_split; /* Last command wasn't sent entirely to server.
	                       First item in `cmdqueue' should be re-sent. */
	GSList *cmdqueue;
	GTimeVal last_cmd; /* last time command was sent to server */

	int max_cmds_at_once; /* How many messages can be sent immediately before timeouting starts */
	int cmd_queue_speed; /* Timeout between sending commands */

	GSList *idles; /* Idle queue - send these commands to server
	                  if there's nothing else to do */

	GSList *ctcpqueue; /* CTCP flood protection - list of tags in idle queue */

	/* /knockout ban list */
	GSList *knockoutlist;
	time_t knockout_lastcheck;

	GSList *lastmsgs; /* List of nicks who last send you msg */
	GHashTable *splits; /* For keeping track of netsplits */

	time_t lag_sent; /* 0 or time when last lag query was sent to server */
	time_t lag_last_check; /* last time we checked lag */
	int lag; /* server lag in milliseconds */

	GSList *channels;
        GSList *queries;

	gpointer chanqueries;
} IRC_SERVER_REC;

IRC_SERVER_REC *irc_server_connect(IRC_SERVER_CONNECT_REC *conn);

/* Return a string of all channels (and keys, if any have them) in server,
   like "#a,#b,#c,#d x,b_chan_key,x,x" or just "#e,#f,#g" */
char *irc_server_get_channels(IRC_SERVER_REC *server);

/* INTERNAL: Free memory used by connection record */
void irc_server_connect_free(IRC_SERVER_CONNECT_REC *rec);

void irc_servers_init(void);
void irc_servers_deinit(void);

#endif
