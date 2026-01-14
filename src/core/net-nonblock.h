#ifndef IRSSI_CORE_NET_NONBLOCK_H
#define IRSSI_CORE_NET_NONBLOCK_H

#include <irssi/src/core/network.h>

typedef void (*NetGethostbynameContinuationFunc)(RESOLVED_IP_REC *, void *);

/* nonblocking gethostbyname(), Cancellable of the resolver child is returned. */
GCancellable *net_gethostbyname_nonblock(const char *addr, GResolverNameLookupFlags flags,
                                         NetGethostbynameContinuationFunc cont, void *cont_data);

#endif
