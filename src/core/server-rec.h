/* SERVER_REC definition, used for inheritance */

int type; /* module_get_uniq_id("SERVER", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

int refcount;

STRUCT_SERVER_CONNECT_REC *connrec;
time_t connect_time; /* connection time */
time_t real_connect_time; /* time when server replied that we really are connected */

char *tag; /* tag name for addressing server */
char *nick; /* current nick */

unsigned int connected:1; /* Connected to server */
unsigned int disconnected:1; /* Disconnected, waiting for refcount to drop zero */
unsigned int connection_lost:1; /* Connection lost unintentionally */
unsigned int session_reconnect:1; /* Connected to this server with /UPGRADE */
unsigned int no_reconnect:1; /* Don't reconnect to server */

NET_SENDBUF_REC *handle;
int readtag; /* input tag */

/* for net_connect_nonblock() */
GIOChannel *connect_pipe[2];
int connect_tag;
int connect_pid;

RAWLOG_REC *rawlog;
GHashTable *module_data;

char *version; /* server version */
char *away_reason;
char *last_invite; /* channel where you were last invited */
unsigned int server_operator:1;
unsigned int usermode_away:1;
unsigned int banned:1; /* not allowed to connect to this server */
unsigned int dns_error:1; /* DNS said the host doesn't exist */

GTimeVal lag_sent; /* 0 or time when last lag query was sent to server */
time_t lag_last_check; /* last time we checked lag */
int lag; /* server lag in milliseconds */

GSList *channels;
GSList *queries;

/* -- support for multiple server types -- */

/* -- must not be NULL: -- */
/* join to a number of channels, channels are specified in `data' separated
   with commas. there can exist other information after first space like
   channel keys etc. */
void (*channels_join)(SERVER_REC *server, const char *data, int automatic);
/* returns true if `flag' indicates a nick flag (op/voice/halfop) */
int (*isnickflag)(SERVER_REC *server, char flag);
/* returns true if `data' indicates a channel */
int (*ischannel)(SERVER_REC *server, const char *data);
/* returns all nick flag characters in order op, voice, halfop. If some
   of them aren't supported '\0' can be used. */
const char *(*get_nick_flags)(SERVER_REC *server);
/* send public or private message to server */
void (*send_message)(SERVER_REC *server, const char *target,
		     const char *msg, int target_type);

/* -- Default implementations are used if NULL -- */
CHANNEL_REC *(*channel_find_func)(SERVER_REC *server, const char *name);
QUERY_REC *(*query_find_func)(SERVER_REC *server, const char *nick);
int (*mask_match_func)(const char *mask, const char *data);
/* returns true if `msg' was meant for `nick' */
int (*nick_match_msg)(const char *nick, const char *msg);

#undef STRUCT_SERVER_CONNECT_REC
