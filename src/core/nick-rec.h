/* NICK_REC definition, used for inheritance */

int type; /* module_get_uniq_id("NICK", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

time_t last_check; /* last time gone was checked */

char *nick;
char *host;
char *realname;
int hops;

/* status in server */
unsigned int gone:1;
unsigned int serverop:1;

/* status in channel */
unsigned int send_massjoin:1; /* Waiting to be sent in massjoin signal */
unsigned int op:1;
unsigned int halfop:1;
unsigned int voice:1;
char prefixes[MAX_USER_PREFIXES+1];

/*GHashTable *module_data;*/

void *unique_id; /* unique ID to use for comparing if one nick is in another channels,
		    or NULL = nicks are unique, just keep comparing them. */
NICK_REC *next; /* support for multiple identically named nicks */
