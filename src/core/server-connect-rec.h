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

char *tls_cert;
char *tls_pkey;
char *tls_pass;
char *tls_cafile;
char *tls_capath;
char *tls_ciphers;
char *tls_pinned_cert;
char *tls_pinned_pubkey;

GIOChannel *connect_handle; /* connect using this handle */

/* when reconnecting, the old server status */
unsigned int reconnection:1; /* we're trying to reconnect a connected server */
unsigned int reconnecting:1; /* we're trying to reconnect any connection */
unsigned int no_autojoin_channels:1; /* don't autojoin any channels */
unsigned int no_autosendcmd:1; /* don't execute autosendcmd */
unsigned int unix_socket:1; /* Connect using named unix socket */
unsigned int use_tls:1; /* this connection uses TLS */
unsigned int tls_verify:1;
unsigned int no_connect:1; /* don't connect() at all, it's done by plugin */
char *channels;
char *away_reason;
