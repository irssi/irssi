#ifndef __DCC_H
#define __DCC_H

#include "network.h"

enum
{
    DCC_TYPE_CHAT = 1,
    DCC_TYPE_SEND,
    DCC_TYPE_GET,
    DCC_TYPE_RESUME,
    DCC_TYPE_ACCEPT
};

enum
{
    DCC_GET_DEFAULT = 0,
    DCC_GET_OVERWRITE,
    DCC_GET_RENAME,
    DCC_GET_RESUME
};

#define SWAP_SENDGET(a) ((a) == DCC_TYPE_SEND ? DCC_TYPE_GET : \
                         (a) == DCC_TYPE_GET ? DCC_TYPE_SEND : (a))

typedef struct DCC_REC
{
	int type;
	GHashTable *module_data;

	IRC_SERVER_REC *server;
	gchar *nick;

	struct DCC_REC *chat; /* if the request came through DCC chat */

	gchar *ircnet;
	gchar *mynick;

	gchar *arg;
	gchar *file; /* file name we're really moving, arg is just the reference.. */

	time_t created;
	gint dcc_type;

	IPADDR addr; /* address we're connected in */
	gchar addrstr[MAX_IP_LEN]; /* in readable form */
	gint port; /* port we're connected in */

	glong size, transfd, skipped; /* file size / bytes transferred / skipped at start */
	gint handle; /* socket handle */
	gint tagread, tagwrite;
	gint fhandle; /* file handle */
	time_t starttime; /* transfer start time */
	gint trans_bytes;

	gboolean fastsend; /* fastsending (just in case that global fastsend toggle changes while transferring..) */
	gboolean waitforend; /* DCC fast send: file is sent, just wait for the replies from the other side */
	gboolean gotalldata; /* DCC fast send: got all acks from the other end (needed to make sure the end of transfer works right) */
	gint get_type; /* DCC get: what to do if file exists? */

	gboolean mirc_ctcp; /* DCC chat: Send CTCPs without the CTCP_MESSAGE prefix */
	gboolean destroyed; /* We're about to destroy this DCC recond */

	/* read counter buffer */
	gchar read_buf[4];
	gint read_pos;

	gchar *databuf; /* buffer for receiving/transmitting data */
	gint databufsize;
}
DCC_REC;

extern GSList *dcc_conns;

void dcc_init(void);
void dcc_deinit(void);

/* Find DCC record, arg can be NULL */
DCC_REC *dcc_find_item(gint type, gchar *nick, gchar *arg);
DCC_REC *dcc_find_by_port(gchar *nick, gint port);

gchar *dcc_type2str(gint type);
gint dcc_str2type(gchar *type);
gchar *dcc_make_address(IPADDR *ip);

DCC_REC *dcc_create(gint type, gint handle, gchar *nick, gchar *arg, IRC_SERVER_REC *server, DCC_REC *chat);
void dcc_destroy(DCC_REC *dcc);

void dcc_ctcp_message(gchar *target, IRC_SERVER_REC *server, DCC_REC *chat, gboolean notice, gchar *msg);

#endif
