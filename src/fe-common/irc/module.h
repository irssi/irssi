#include "common.h"

#define MODULE_NAME "fe-common/irc"

typedef struct {
	time_t time;
	char *nick;
} LAST_MSG_REC;

typedef struct {
	GSList *lastmsgs; /* List of nicks who last send you msg */
} MODULE_SERVER_REC;

typedef struct {
	GSList *lastmsgs; /* List of nicks who last send message */
	GSList *lastownmsgs; /* List of nicks who last send message to you */
} MODULE_CHANNEL_REC;
