#ifndef __CAPSICUM_H
#define __CAPSICUM_H

gboolean capsicum_enabled(void);
int capsicum_net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
int capsicum_net_gethostbyname(const char *addr, IPADDR *ip4, IPADDR *ip6);

void capsicum_init(void);
void capsicum_deinit(void);

#endif
