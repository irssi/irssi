#ifndef __SERVER_IDLE_H
#define __SERVER_IDLE_H

/* Add new idle command to queue */
int server_idle_add(IRC_SERVER_REC *server, const char *cmd, const char *arg, int last, ...);

/* Add new idle command to first of queue */
int server_idle_add_first(IRC_SERVER_REC *server, const char *cmd, const char *arg, int last, ...);

/* Add new idle command to specified position of queue */
int server_idle_insert(IRC_SERVER_REC *server, const char *cmd, const char *arg, int tag, int last, ...);

/* Check if record is still in queue */
int server_idle_find(IRC_SERVER_REC *server, int tag);

/* Remove record from idle queue */
int server_idle_remove(IRC_SERVER_REC *server, int tag);

void servers_idle_init(void);
void servers_idle_deinit(void);

#endif
