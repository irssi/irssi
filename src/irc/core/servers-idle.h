#ifndef __SERVERS_IDLE_H
#define __SERVERS_IDLE_H

/* Add new idle command to queue */
int server_idle_add_redir(IRC_SERVER_REC *server, const char *cmd,
			  const char *redirect_cmd, int count,
			  const char *arg, int remote,
			  const char *failure_signal, ...);
#define server_idle_add(server, cmd) \
        server_idle_add_redir(server, cmd, NULL, 0, NULL, 0, NULL, NULL)

/* Add new idle command to first of queue */
int server_idle_add_first_redir(IRC_SERVER_REC *server, const char *cmd,
				const char *redirect_cmd, int count,
				const char *arg, int remote,
				const char *failure_signal, ...);
#define server_idle_add_first(server, cmd) \
        server_idle_add_first_redir(server, cmd, NULL, 0, NULL, 0, NULL, NULL)

/* Add new idle command to specified position of queue */
int server_idle_insert_redir(IRC_SERVER_REC *server, const char *cmd, int tag,
			     const char *redirect_cmd, int count,
			     const char *arg, int remote,
			     const char *failure_signal, ...);
#define server_idle_insert(server, cmd, tag) \
        server_idle_insert_redir(server, cmd, tag, NULL, 0, NULL, 0, NULL, NULL)

/* Check if record is still in queue */
int server_idle_find(IRC_SERVER_REC *server, int tag);

/* Remove record from idle queue */
int server_idle_remove(IRC_SERVER_REC *server, int tag);

void servers_idle_init(void);
void servers_idle_deinit(void);

#endif
