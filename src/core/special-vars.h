#ifndef __SPECIAL_VARS_H
#define __SPECIAL_VARS_H

#include "servers.h"

typedef char* (*EXPANDO_FUNC)
	(SERVER_REC *server, void *item, int *free_ret);
typedef char* (*SPECIAL_HISTORY_FUNC)
	(const char *text, void *item, int *free_ret);

/* Parse and expand text after '$' character. return value has to be
   g_free()'d if `free_ret' is TRUE. */
char *parse_special(char **cmd, SERVER_REC *server, void *item,
		    char **arglist, int *free_ret, int *arg_used);

/* parse the whole string. $ and \ chars are replaced */
char *parse_special_string(const char *cmd, SERVER_REC *server, void *item,
			   const char *data, int *arg_used);

/* execute the commands in string - commands can be split with ';' */
void eval_special_string(const char *cmd, const char *data,
			 SERVER_REC *server, void *item);

/* Create expando - overrides any existing ones. */
void expando_create(const char *key, EXPANDO_FUNC func);
/* Destroy expando */
void expando_destroy(const char *key, EXPANDO_FUNC func);

void special_history_func_set(SPECIAL_HISTORY_FUNC func);

void special_vars_init(void);
void special_vars_deinit(void);

#endif
