#ifndef __CAPSICUM_H
#define __CAPSICUM_H

gboolean capsicum_enabled(void);
int capsicum_net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
int capsicum_net_gethostbyname(const char *addr, IPADDR *ip4, IPADDR *ip6);
int capsicum_open(const char *path, int flags, int mode);
int capsicum_open_wrapper(const char *path, int flags, int mode);
void capsicum_mkdir_with_parents(const char *path, int mode);
void capsicum_mkdir_with_parents_wrapper(const char *path, int mode);

void capsicum_init(void);
void capsicum_deinit(void);

#endif /* !__CAPSICUM_H */
