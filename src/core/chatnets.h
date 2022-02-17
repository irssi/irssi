#ifndef IRSSI_CORE_CHATNETS_H
#define IRSSI_CORE_CHATNETS_H

#include <irssi/src/core/modules.h>

/* Returns CHATNET_REC if it's chatnet, NULL if it isn't. */
#define CHATNET(chatnet) \
	MODULE_CHECK_CAST(chatnet, CHATNET_REC, type, "CHATNET")

#define IS_CHATNET(chatnet) \
	(CHATNET(chatnet) ? TRUE : FALSE)

struct _CHATNET_REC {
#include <irssi/src/core/chatnet-rec.h>
};

extern GSList *chatnets; /* list of available chat networks */

/* add the chatnet to chat networks list */
void chatnet_create(CHATNET_REC *chatnet);
/* remove the chatnet from chat networks list */
void chatnet_remove(CHATNET_REC *chatnet);
/* destroy the chatnet structure. doesn't remove from config file */
void chatnet_destroy(CHATNET_REC *chatnet);

/* Find the chat network by name */
CHATNET_REC *chatnet_find(const char *name);
/* Check if this chatnet is unavailable because the protocol is not loaded */
gboolean chatnet_find_unavailable(const char *name);

void chatnets_init(void);
void chatnets_deinit(void);

#endif
