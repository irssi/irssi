int type; /* should always be "CHATNET" */
int chat_type;

char *name;

char *nick;
char *username;
char *realname;

char *own_host; /* address to use when connecting this server */
char *autosendcmd; /* command to send after connecting to this ircnet */
IPADDR *own_ip; /* resolved own_address if not NULL */
