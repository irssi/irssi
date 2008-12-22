#ifndef __NET_SENDBUFFER_H
#define __NET_SENDBUFFER_H

#define DEFAULT_BUFFER_SIZE 8192
#define MAX_BUFFER_SIZE 1048576

struct _NET_SENDBUF_REC {
        GIOChannel *handle;
        LINEBUF_REC *readbuffer; /* receive buffer */

        int send_tag;
        int bufsize;
        int bufpos;
        char *buffer; /* Buffer is NULL until it's actually needed. */
        int def_bufsize;
        unsigned int dead:1;
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

int net_sendbuffer_receive_line(NET_SENDBUF_REC *rec, char **str, int read_socket);

/* Flush the buffer, blocks until finished. */
void net_sendbuffer_flush(NET_SENDBUF_REC *rec);

/* Returns the socket handle */
GIOChannel *net_sendbuffer_handle(NET_SENDBUF_REC *rec);

#endif
