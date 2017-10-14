int type; /* module_get_uniq_id("CHATNET", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

char *name;

char *nick;
char *username;
char *realname;

char *own_host; /* address to use when connecting this server */
char *autosendcmd; /* command to send after connecting to this ircnet */
IPADDR *own_ip4, *own_ip6; /* resolved own_address if not NULL */
