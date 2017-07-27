#ifndef __CAPSICUM_H
#define __CAPSICUM_H

gboolean capsicum_enabled(void);
int capsicum_net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);

void capsicum_init(void);
void capsicum_deinit(void);

#endif
