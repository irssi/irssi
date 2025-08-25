#ifndef IRSSI_IRC_DCC_DCC_CHAT_H
#define IRSSI_IRC_DCC_DCC_CHAT_H

#include <irssi/src/irc/dcc/dcc.h>

#define DCC_CHAT(dcc) \
	MODULE_CHECK_CAST_MODULE(dcc, CHAT_DCC_REC, type, "DCC", "CHAT")

#define IS_DCC_CHAT(dcc) \
	(DCC_CHAT(dcc) ? TRUE : FALSE)

struct CHAT_DCC_REC {
#include <irssi/src/irc/dcc/dcc-rec.h>

	char *id; /* unique identifier - usually same as nick. */
	NET_SENDBUF_REC *sendbuf;

	unsigned int mirc_ctcp:1; /* Send CTCPs without the CTCP_MESSAGE prefix */
	unsigned int connection_lost:1; /* other side closed connection */
};

#define DCC_CHAT_TYPE module_get_uniq_id_str("DCC", "CHAT")

CHAT_DCC_REC *dcc_chat_find_id(const char *id);

/* Send `data' to dcc chat. */
void dcc_chat_send(CHAT_DCC_REC *dcc, const char *data);

/* Send a CTCP message/notify to target.
   Send the CTCP via DCC chat if `chat' is specified. */
void dcc_ctcp_message(IRC_SERVER_REC *server, const char *target,
		      CHAT_DCC_REC *chat, int notice, const char *msg);

/* If `item' is a query of a =nick, return DCC chat record of nick */
CHAT_DCC_REC *item_get_dcc(WI_ITEM_REC *item);

void dcc_chat_init(void);
void dcc_chat_deinit(void);

#endif
