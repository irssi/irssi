#ifndef __NET_DISCONNECT_H
#define __NET_DISCONNECT_H

/* Try to let the other side close the connection, if it still isn't
   disconnected after certain amount of time, close it ourself */
void net_disconnect_later(GIOChannel *handle);

void net_disconnect_init(void);
void net_disconnect_deinit(void);

#endif
