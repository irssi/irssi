#ifndef __AUTOIGNORE_H
#define __AUTOIGNORE_H

void autoignore_add(IRC_SERVER_REC *server, char *nick, int level);

void autoignore_init(void);
void autoignore_deinit(void);

#endif
