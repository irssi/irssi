/* CHANNEL_REC definition, used for inheritance */

#include "window-item-rec.h"

char *name;
char *topic;
char *topic_by;
time_t topic_time;

GHashTable *nicks; /* list of nicks */
NICK_REC *ownnick; /* our own nick */

unsigned int no_modes:1; /* channel doesn't support modes */
char *mode;
int limit; /* user limit */
char *key; /* password key */

unsigned int chanop:1; /* You're a channel operator */
unsigned int names_got:1; /* Received /NAMES list */
unsigned int wholist:1; /* WHO list got */
unsigned int synced:1; /* Channel synced - all queries done */

unsigned int joined:1; /* Have we even received JOIN event for this channel? */
unsigned int left:1; /* You just left the channel */
unsigned int kicked:1; /* You just got kicked */
unsigned int session_rejoin:1; /* This channel was joined with /UPGRADE */
unsigned int destroying:1;

/* Return the information needed to call SERVER_REC->channels_join() for
   this channel. Usually just the channel name, but may contain also the
   channel key. */
char *(*get_join_data)(CHANNEL_REC *channel);
