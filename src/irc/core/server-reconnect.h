#ifndef __SERVER_RECONNECT_H
#define __SERVER_RECONNECT_H

/* wait for half an hour before trying to reconnect to host where last
   connection failed */
#define FAILED_RECONNECT_WAIT (60*30)

typedef struct {
	int tag;
	time_t next_connect;

	IRC_SERVER_CONNECT_REC *conn;
} RECONNECT_REC;

extern GSList *reconnects;

void servers_reconnect_init(void);
void servers_reconnect_deinit(void);

#endif
