#ifndef __NET_SENDBUFFER_H
#define __NET_SENDBUFFER_H

#define DEFAULT_BUFFER_SIZE 8192

struct _NET_SENDBUF_REC {
        GIOChannel *handle;

        int send_tag;
        int bufsize;
        int bufpos;
        char *buffer; /* Buffer is NULL until it's actually needed. */
};

/* Create new buffer - if `bufsize' is zero or less, DEFAULT_BUFFER_SIZE
   is used */
NET_SENDBUF_REC *net_sendbuffer_create(GIOChannel *handle, int bufsize);
/* Destroy the buffer. `close' specifies if socket handle should be closed. */
void net_sendbuffer_destroy(NET_SENDBUF_REC *rec, int close);

/* Send data, if all of it couldn't be sent immediately, it will be resent
   automatically after a while. Returns -1 if some unrecoverable error
   occured. */
int net_sendbuffer_send(NET_SENDBUF_REC *rec, const void *data, int size);

/* Flush the buffer, blocks until finished. */
void net_sendbuffer_flush(NET_SENDBUF_REC *rec);

/* Returns the socket handle */
GIOChannel *net_sendbuffer_handle(NET_SENDBUF_REC *rec);

void net_sendbuffer_init(void);
void net_sendbuffer_deinit(void);

#endif
