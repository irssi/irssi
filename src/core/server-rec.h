/* SERVER_REC definition, used for inheritance */

int type; /* should always be "SERVER" */
int chat_type;

STRUCT_SERVER_CONNECT_REC *connrec;
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
int server_operator:1;
int usermode_away:1;
int banned:1; /* not allowed to connect to this server */

GSList *channels;
GSList *queries;

/* support for multiple server types */
void *channel_find_func;
void *query_find_func;
int channel_type;
int query_type;

void *mask_match_func;

#undef STRUCT_SERVER_CONNECT_REC
