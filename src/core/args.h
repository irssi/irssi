#ifndef IRSSI_CORE_ARGS_H
#define IRSSI_CORE_ARGS_H

void args_register(GOptionEntry *options);
void args_execute(int argc, char *argv[]);

#endif
