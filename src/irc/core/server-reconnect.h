#ifndef __SERVER_RECONNECT_H
#define __SERVER_RECONNECT_H

typedef struct {
	int tag;
	time_t next_connect;

	IRC_SERVER_CONNECT_REC *conn;
} RECONNECT_REC;

extern GSList *reconnects;

void servers_reconnect_init(void);
void servers_reconnect_deinit(void);

#endif
