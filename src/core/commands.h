#ifndef __COMMANDS_H
#define __COMMANDS_H

#include "signals.h"

typedef struct {
	char *category;
	char *cmd;
}
COMMAND_REC;

enum {
	CMDERR_PARAM, /* invalid parameter */
	CMDERR_NOT_ENOUGH_PARAMS, /* not enough parameters given */
	CMDERR_NOT_CONNECTED, /* not connected to IRC server */
	CMDERR_NOT_JOINED, /* not joined to any channels in this window */
	CMDERR_GETSOCKNAME, /* getsockname() failed */
	CMDERR_LISTEN, /* listen() failed */
	CMDERR_MULTIPLE_MATCHES, /* multiple matches found, didn't do anything */
	CMDERR_NICK_NOT_FOUND, /* nick not found */
	CMDERR_CHAN_NOT_FOUND, /* channel not found */
	CMDERR_SERVER_NOT_FOUND, /* server not found */
	CMDERR_CHAN_NOT_SYNCED, /* channel not fully synchronized yet */
	CMDERR_NOT_GOOD_IDEA /* not good idea to do, -yes overrides this */
};

#define cmd_return_error(a) { signal_emit("error command", 1, GINT_TO_POINTER(a)); return; }
#define cmd_param_error(a) { g_free(params); cmd_return_error(a); }

extern GSList *commands;
extern char *current_command;

void command_bind(const char *cmd, const char *category, SIGNAL_FUNC func);
void command_unbind(const char *cmd, SIGNAL_FUNC func);

void command_runsub(const char *cmd, const char *data, void *p1, void *p2);

/* count can have these flags: */
#define PARAM_WITHOUT_FLAGS(a) ((a) & 0x00ffffff)
/* cmd_get_params() */
#define PARAM_FLAG_GETREST 0x02000000
/* optional arguments (-cmd -cmd2 -cmd3) */
#define PARAM_FLAG_OPTARGS 0x04000000
/* arguments can have arguments too. Example:

     -cmd arg -noargcmd -cmd2 "another arg -optnumarg rest of the text

   You would call this with:

   args = "cmd cmd2 @optnumarg";
   cmd_get_params(data, 5 | PARAM_FLAG_MULTIARGS | PARAM_FLAG_GETREST,
                  &args, &arg_cmd, &arg_cmd2, &arg_optnum, &rest);

   The variables are filled as following:

   args = "-cmd -noargcmd -cmd2 -optnumarg"
   arg_cmd = "arg"
   arg_cmd2 = "another arg"
   rest = "rest of the text"
   arg_optnum = "" - this is because "rest" isn't a numeric value
*/
#define PARAM_FLAG_MULTIARGS 0x08000000

char *cmd_get_param(char **data);
char *cmd_get_params(const char *data, int count, ...);

typedef char* (*CMD_GET_FUNC) (const char *data, int *count, va_list *args);
void cmd_get_add_func(CMD_GET_FUNC func);
void cmd_get_remove_func(CMD_GET_FUNC func);

void commands_init(void);
void commands_deinit(void);

#endif
