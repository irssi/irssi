#ifndef IRSSI_IRC_DCC_DCC_SERVER_H
#define IRSSI_IRC_DCC_DCC_SERVER_H

#include <irssi/src/irc/dcc/dcc.h>

#define DCC_SERVER(dcc) \
	MODULE_CHECK_CAST_MODULE(dcc, SERVER_DCC_REC, type, "DCC", "SERVER")

#define IS_DCC_SERVER(dcc) \
	(DCC_SERVER(dcc) ? TRUE : FALSE)

struct SERVER_DCC_REC {
#include <irssi/src/irc/dcc/dcc-rec.h>
	NET_SENDBUF_REC *sendbuf;

	unsigned int accept_send:1;   /* Accept SEND connections */
	unsigned int accept_chat:1;   /* Accept CHAT connections */
	unsigned int accept_fserve:1; /* Accept FSERVE connections */
	unsigned int connection_established:1; /* We have made a connection */
};

#define DCC_SERVER_TYPE module_get_uniq_id_str("DCC", "SERVER")

typedef struct SERVER_DCC_REC SERVER_DCC_REC;

void dcc_server_init(void);
void dcc_server_deinit(void);

#endif
