#ifndef __SERVER_H
#define __SERVER_H

#ifndef __NETWORK_H
typedef struct _ipaddr IPADDR;
#endif

/* all strings should be either NULL or dynamically allocated */
/* address and nick are mandatory, rest are optional */
typedef struct {
	/* if we're connecting via proxy, or just NULLs */
	char *proxy;
	int proxy_port;
	char *proxy_string;

	char *address;
	int port;
	char *ircnet;

	IPADDR *own_ip;

	char *password;
	char *nick;
	char *username;
	char *realname;

	/* when reconnecting, the old server status */
	int reconnection:1; /* we're trying to reconnect */
	char *channels;
	char *away_reason;
	char *usermode;
} SERVER_CONNECT_REC;

typedef struct {
	int type; /* server type */

	SERVER_CONNECT_REC *connrec;
	time_t connect_time; /* connection time */
	time_t real_connect_time; /* time when server replied that we really are connected */

	char *tag; /* tag name for addressing server */
	char *nick; /* current nick */

	int connected:1; /* connected to server */
	int connection_lost:1; /* Connection lost unintentionally */

        void *handle; /* NET_SENDBUF_REC socket */
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

	char *version; /* server version */
	char *away_reason;
	int usermode_away:1;
	int banned:1; /* not allowed to connect to this server */
} SERVER_REC;

extern GSList *servers, *lookup_servers;

/* Connect to server */
int server_connect(SERVER_REC *server);
/* Disconnect from server */
void server_disconnect(SERVER_REC *server);

SERVER_REC *server_find_tag(const char *tag);
SERVER_REC *server_find_ircnet(const char *ircnet);

void servers_init(void);
void servers_deinit(void);

#endif
