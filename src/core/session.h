#ifndef __SESSION_H
#define __SESSION_H

extern char *irssi_binary;

void session_set_binary(const char *path);
void session_upgrade(void);

void session_register_options(void);
void session_init(void);
void session_deinit(void);

#endif
