#ifndef __AUTOIGNORE_H
#define __AUTOIGNORE_H

typedef struct {
	char *nick;
	int timeleft;
	int level;
} AUTOIGNORE_REC;

GSList *server_autoignores(IRC_SERVER_REC *server);

void autoignore_add(IRC_SERVER_REC *server, const char *nick, int level);
int autoignore_remove(IRC_SERVER_REC *server, const char *mask, int level);

void autoignore_init(void);
void autoignore_deinit(void);

#endif
