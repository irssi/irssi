#ifndef __CHATNETS_H
#define __CHATNETS_H

#include "modules.h"

/* Returns CHATNET_REC if it's chatnet, NULL if it isn't. */
#define CHATNET(chatnet) \
	MODULE_CHECK_CAST(chatnet, CHATNET_REC, type, "CHATNET")

#define IS_CHATNET(chatnet) \
	(CHATNET(chatnet) ? TRUE : FALSE)

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
