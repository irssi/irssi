/* SERVER_CONNECT_REC definition, used for inheritance */

int type; /* module_get_uniq_id("SERVER CONNECT", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

/* if we're connecting via proxy, or just NULLs */
char *proxy;
int proxy_port;
char *proxy_string, *proxy_password;

unsigned short family; /* 0 = don't care, AF_INET or AF_INET6 */
char *address;
int port;
char *chatnet;

IPADDR *own_ip4, *own_ip6;

char *password;
char *nick;
char *username;
char *realname;

/* when reconnecting, the old server status */
unsigned int reconnection:1; /* we're trying to reconnect */
char *channels;
char *away_reason;
