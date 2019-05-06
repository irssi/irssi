#ifndef IRSSI_IRC_CORE_CTCP_H
#define IRSSI_IRC_CORE_CTCP_H

/* Register/unregister CTCP command, so it shows in CTCP CLIENTINFO */
void ctcp_register(const char *name);
void ctcp_unregister(const char *name);

/* Send CTCP reply with flood protection */
void ctcp_send_reply(IRC_SERVER_REC *server, const char *data);

void ctcp_init(void);
void ctcp_deinit(void);

#endif
