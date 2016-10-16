int type; /* module_get_uniq_id("SERVER SETUP", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

char *chatnet;

unsigned short family; /* 0 = default, AF_INET or AF_INET6 */
char *address;
int port;
char *password;

int sasl_mechanism;
char *sasl_password;

char *tls_cert;
char *tls_pkey;
char *tls_pass;
char *tls_cafile;
char *tls_capath;
char *tls_ciphers;
char *tls_pinned_cert;
char *tls_pinned_pubkey;

char *own_host; /* address to use when connecting this server */
IPADDR *own_ip4, *own_ip6; /* resolved own_address if not NULL */

time_t last_connect; /* to avoid reconnecting too fast.. */

unsigned int autoconnect:1;
unsigned int no_proxy:1;
unsigned int last_failed:1; /* if last connection attempt failed */
unsigned int banned:1; /* if we're banned from this server */
unsigned int dns_error:1; /* DNS said the host doesn't exist */
unsigned int use_tls:1; /* this connection uses TLS */
unsigned int tls_verify:1;

GHashTable *module_data;
