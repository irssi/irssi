#ifndef __SESSION_H
#define __SESSION_H

void session_set_binary(const char *path);
void session_upgrade(void);

void session_init(void);
void session_deinit(void);

#endif
