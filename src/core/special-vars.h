#ifndef __SPECIAL_VARS_H
#define __SPECIAL_VARS_H

#include "signals.h"

#define PARSE_FLAG_GETNAME	0x01 /* return argument name instead of it's value */
#define PARSE_FLAG_ISSET_ANY	0x02 /* arg_used field specifies that at least one of the $variables was non-empty */
#define PARSE_FLAG_ESCAPE_VARS  0x04 /* if any arguments/variables contain % chars, escape them with another % */
#define PARSE_FLAG_ESCAPE_THEME 0x08 /* if any arguments/variables contain { or } chars, escape them with % */
#define PARSE_FLAG_ONLY_ARGS	0x10 /* expand only arguments ($0 $1 etc.) but no other $variables */

typedef char* (*SPECIAL_HISTORY_FUNC)
	(const char *text, void *item, int *free_ret);

/* Parse and expand text after '$' character. return value has to be
   g_free()'d if `free_ret' is TRUE. */
char *parse_special(char **cmd, SERVER_REC *server, void *item,
		    char **arglist, int *free_ret, int *arg_used, int flags);

/* parse the whole string. $ and \ chars are replaced */
char *parse_special_string(const char *cmd, SERVER_REC *server, void *item,
			   const char *data, int *arg_used, int flags);

/* execute the commands in string - commands can be split with ';' */
void eval_special_string(const char *cmd, const char *data,
			 SERVER_REC *server, void *item);

void special_history_func_set(SPECIAL_HISTORY_FUNC func);

void special_vars_add_signals(const char *text,
			      int funccount, SIGNAL_FUNC *funcs);
void special_vars_remove_signals(const char *text,
				 int funccount, SIGNAL_FUNC *funcs);
/* Returns [<signal id>, EXPANDO_ARG_xxx, <signal id>, ..., -1] */
int *special_vars_get_signals(const char *text);

#endif
