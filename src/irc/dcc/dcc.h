#ifndef __DCC_H
#define __DCC_H

#include "network.h"

enum {
	DCC_TYPE_CHAT = 1,
	DCC_TYPE_SEND,
	DCC_TYPE_GET,
	DCC_TYPE_RESUME,
	DCC_TYPE_ACCEPT
};

enum {
	DCC_GET_RENAME = 0, /* this also acts as default */
	DCC_GET_OVERWRITE,
	DCC_GET_RESUME
};

#define SWAP_SENDGET(a) ((a) == DCC_TYPE_SEND ? DCC_TYPE_GET : \
                         (a) == DCC_TYPE_GET ? DCC_TYPE_SEND : (a))

typedef struct DCC_REC {
	int type;
	time_t created;

	IRC_SERVER_REC *server;
	char *nick;

	struct DCC_REC *chat; /* if the request came through DCC chat */

	char *ircnet;
	char *mynick;

	char *arg;
	char *file; /* file name we're really moving, arg is just the reference.. */

	IPADDR addr; /* address we're connected in */
	char addrstr[MAX_IP_LEN]; /* in readable form */
	int port; /* port we're connected in */

	long size, transfd, skipped; /* file size / bytes transferred / skipped at start */
	GIOChannel *handle; /* socket handle */
	NET_SENDBUF_REC *sendbuf;
	int tagconn, tagread, tagwrite;
	int fhandle; /* file handle */
	time_t starttime; /* transfer start time */
	int trans_bytes;

	int get_type; /* DCC get: what to do if file exists? */

	unsigned int fastsend:1; /* fastsending (just in case that global fastsend toggle changes while transferring..) */
	unsigned int waitforend:1; /* DCC fast send: file is sent, just wait for the replies from the other side */
	unsigned int gotalldata:1; /* DCC fast send: got all acks from the other end (needed to make sure the end of transfer works right) */

	unsigned int mirc_ctcp:1; /* DCC chat: Send CTCPs without the CTCP_MESSAGE prefix */
	unsigned int connection_lost:1; /* DCC chat: other side closed connection */
	unsigned int destroyed:1; /* We're about to destroy this DCC recond */

	/* read/write counter buffer */
	char count_buf[4];
	int count_pos;

	char *databuf; /* buffer for receiving/transmitting data */
	int databufsize;

	GHashTable *module_data;
} DCC_REC;

extern GSList *dcc_conns;

void dcc_init(void);
void dcc_deinit(void);

/* Find DCC record, arg can be NULL */
DCC_REC *dcc_find_item(int type, const char *nick, const char *arg);
DCC_REC *dcc_find_by_port(const char *nick, int port);

const char *dcc_type2str(int type);
int dcc_str2type(const char *type);
void dcc_make_address(IPADDR *ip, char *host);

DCC_REC *dcc_create(int type, GIOChannel *handle, const char *nick,
		    const char *arg, IRC_SERVER_REC *server, DCC_REC *chat);
void dcc_destroy(DCC_REC *dcc);

/* Send a CTCP message/notify to target. Send the CTCP via DCC chat if
   `chat' is specified. */
void dcc_ctcp_message(IRC_SERVER_REC *server, const char *target,
		      DCC_REC *chat, int notice, const char *msg);

/* Send `data' to dcc chat. */
void dcc_chat_send(DCC_REC *dcc, const char *data);
/* If `item' is a query of a =nick, return DCC chat record of nick */
DCC_REC *item_get_dcc(void *item);

/* reject DCC request */
void dcc_reject(DCC_REC *dcc, IRC_SERVER_REC *server);

#endif
