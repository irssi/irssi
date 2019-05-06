#ifndef IRSSI_IRC_FLOOD_AUTOIGNORE_H
#define IRSSI_IRC_FLOOD_AUTOIGNORE_H

void autoignore_add(IRC_SERVER_REC *server, char *nick, int level);

void autoignore_init(void);
void autoignore_deinit(void);

#endif
