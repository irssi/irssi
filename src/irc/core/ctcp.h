#ifndef __CTCP_H
#define __CTCP_H

void ctcp_init(void);
void ctcp_deinit(void);

/* Send CTCP reply with flood protection */
void ctcp_send_reply(SERVER_REC *server, gchar *data);

#endif
