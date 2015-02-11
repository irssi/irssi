#ifndef __IRC_CAP_H
#define __IRC_CAP_H

void cap_init(void);
void cap_deinit(void);
int cap_toggle (IRC_SERVER_REC *server, char *cap, int enable);
void cap_finish_negotiation (IRC_SERVER_REC *server);

#endif
