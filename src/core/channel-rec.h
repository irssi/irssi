/* CHANNEL_REC definition, used for inheritance */

#include "window-item-rec.h"

char *topic;
char *topic_by;
time_t topic_time;
GHashTable *nicks; /* list of nicks */

int no_modes:1; /* channel doesn't support modes */
char *mode;
int limit; /* user limit */
char *key; /* password key */

int chanop:1; /* You're a channel operator */
int names_got:1; /* Received /NAMES list */
int wholist:1; /* WHO list got */
int synced:1; /* Channel synced - all queries done */

int joined:1; /* Have we even received JOIN event for this channel? */
int left:1; /* You just left the channel */
int kicked:1; /* You just got kicked */
int destroying:1;

GSList *lastmsgs; /* List of nicks who last send message */
GSList *lastownmsgs; /* List of nicks who last send message to you */
