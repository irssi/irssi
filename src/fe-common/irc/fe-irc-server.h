#ifndef __FE_IRC_SERVER_H
#define __FE_IRC_SERVER_H

const char *get_visible_target(IRC_SERVER_REC *server, const char *target);

void fe_irc_server_init(void);
void fe_irc_server_deinit(void);

#endif
