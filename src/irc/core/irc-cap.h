#ifndef __IRC_CAP_H
#define __IRC_CAP_H

void irc_cap_init(void);
void irc_cap_deinit(void);
int irc_cap_toggle (IRC_SERVER_REC *server, char *cap, int enable);
void irc_cap_finish_negotiation (IRC_SERVER_REC *server);

#endif
