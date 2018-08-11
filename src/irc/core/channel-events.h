#ifndef __CHANNEL_EVENTS_H
#define __CHANNEL_EVENTS_H

#include "irc.h"

/* Not private for tests. */
void event_topic_get(IRC_SERVER_REC *, const char *);
void event_topic(IRC_SERVER_REC *, const char *,
			const char *, const char *);
void event_topic_info(IRC_SERVER_REC *, const char *);

#endif
