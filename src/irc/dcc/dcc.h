#ifndef __DCC_H
#define __DCC_H

#include "modules.h"
#include "network.h"

#define DCC(dcc) ((DCC_REC *) (dcc))

typedef struct CHAT_DCC_REC CHAT_DCC_REC;

typedef struct {
#include "dcc-rec.h"
} DCC_REC;

/* fully connected? */
#define dcc_is_connected(dcc) \
        ((dcc)->starttime != 0)

/* not connected, we're waiting for other side to connect */
#define dcc_is_listening(dcc) \
        ((dcc)->handle != NULL && (dcc)->starttime == 0)

/* not connected, waiting for user to accept it */
#define dcc_is_waiting_user(dcc) \
        ((dcc)->handle == NULL)

/* passive DCC */
#define dcc_is_passive(dcc) \
	((dcc)->pasv_id >= 0)
		
extern GSList *dcc_conns;

void dcc_register_type(const char *type);
void dcc_unregister_type(const char *type);

int dcc_str2type(const char *str);
#define dcc_type2str(type) (module_find_id_str("DCC", type))

/* Initialize DCC record */
void dcc_init_rec(DCC_REC *dcc, IRC_SERVER_REC *server, CHAT_DCC_REC *chat,
		  const char *nick, const char *arg);
void dcc_destroy(DCC_REC *dcc);

/* Find waiting DCC requests (non-connected) */
DCC_REC *dcc_find_request_latest(int type);
DCC_REC *dcc_find_request(int type, const char *nick, const char *arg);

/* IP <-> string for DCC CTCP messages.
   `str' must be at least MAX_IP_LEN bytes.
   If /SET dcc_own_ip is set, dcc_ip2str() always returns it. */
void dcc_ip2str(IPADDR *ip, char *str);
void dcc_str2ip(const char *str, IPADDR *ip);

/* Start listening for incoming connections */
GIOChannel *dcc_listen(GIOChannel *iface, IPADDR *ip, int *port);
/* Connect to specified IP address using the correct own_ip. */
GIOChannel *dcc_connect_ip(IPADDR *ip, int port);

/* Close DCC - sends "dcc closed" signal and calls dcc_destroy() */
void dcc_close(DCC_REC *dcc);
/* Reject a DCC request */
void dcc_reject(DCC_REC *dcc, IRC_SERVER_REC *server);

void dcc_init(void);
void dcc_deinit(void);

#endif
