/* SERVER_CONNECT_REC definition, used for inheritance */

int type; /* module_get_uniq_id("SERVER CONNECT", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

int refcount;

/* if we're connecting via proxy, or just NULLs */
char *proxy;
int proxy_port;
char *proxy_string, *proxy_string_after, *proxy_password;

unsigned short family; /* 0 = don't care, AF_INET or AF_INET6 */
char *tag; /* try to keep this tag when connected to server */
char *address;
int port;
char *chatnet;

IPADDR *own_ip4, *own_ip6;

char *password;
char *nick;
char *username;
char *realname;

GIOChannel *connect_handle; /* connect using this handle */

/* when reconnecting, the old server status */
unsigned int reconnection:1; /* we're trying to reconnect */
unsigned int no_autojoin_channels:1; /* don't autojoin any channels */
unsigned int unix_socket:1; /* Connect using named unix socket */
unsigned int use_ssl:1; /* this connection uses SSL */
char *channels;
char *away_reason;
