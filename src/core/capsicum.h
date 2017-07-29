#ifndef __CAPSICUM_H
#define __CAPSICUM_H

gboolean capsicum_enabled(void);
int capsicum_net_connect_ip(IPADDR *ip, int port, IPADDR *my_ip);
int capsicum_net_gethostbyname(const char *addr, IPADDR *ip4, IPADDR *ip6);
int capsicum_open(const char *path, int flags, int mode);
void capsicum_mkdir_with_parents(const char *path, int mode);

#ifdef HAVE_CAPSICUM
int capsicum_open_wrapper(const char *path, int flags, int mode);
void capsicum_mkdir_with_parents_wrapper(const char *path, int mode);
#else
#define	capsicum_open_wrapper(P, F, M)			\
	open(P, F, M)
#define	capsicum_mkdir_with_parents_wrapper(P, M)	\
	g_mkdir_with_parents(P, M)
#endif

void capsicum_init(void);
void capsicum_deinit(void);

#endif /* !__CAPSICUM_H */
