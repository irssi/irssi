#ifndef __CHATNETS_H
#define __CHATNETS_H

#include "modules.h"

#define IS_CHATNET(chatnet) \
	((chatnet) != NULL && \
	 module_find_id("CHATNET", (chatnet)->type) != -1)

/* Returns CHATNET_REC if it's chatnet, NULL if it isn't. */
#define CHATNET(chatnet) \
	(IS_CHATNET(chatnet) ? (CHATNET_REC *) (chatnet) : NULL)

typedef struct {
#include "chatnet-rec.h"
} CHATNET_REC;

extern GSList *chatnets; /* list of available chat networks */

/* read/save to configuration file */
void chatnet_read(CHATNET_REC *chatnet, void *node);
void *chatnet_save(CHATNET_REC *chatnet, void *parentnode);

/* add the chatnet to chat networks list */
void chatnet_create(CHATNET_REC *chatnet);
/* remove the chatnet from chat networks list */
void chatnet_remove(CHATNET_REC *chatnet);
/* destroy the chatnet structure. doesn't remove from config file */
void chatnet_destroy(CHATNET_REC *chatnet);

/* Find the irc network by name */
CHATNET_REC *chatnet_find(const char *name);

void chatnets_init(void);
void chatnets_deinit(void);

#endif
