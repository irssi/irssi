#ifndef __COMMANDS_H
#define __COMMANDS_H

#include "signals.h"

typedef struct {
	char *name;
	char *options;
        GSList *signals;
} COMMAND_MODULE_REC;

typedef struct {
        GSList *modules;
	char *category;
	char *cmd;
	char **options; /* combined from modules[..]->options */
} COMMAND_REC;

enum {
	CMDERR_OPTION_UNKNOWN = -3, /* unknown -option */
	CMDERR_OPTION_AMBIGUOUS = -2, /* ambiguous -option */
	CMDERR_OPTION_ARG_MISSING = -1, /* argument missing for -option */

	CMDERR_UNKNOWN, /* unknown command */
	CMDERR_AMBIGUOUS, /* ambiguous command */

        CMDERR_ERRNO, /* get the error from errno */
	CMDERR_NOT_ENOUGH_PARAMS, /* not enough parameters given */
	CMDERR_NOT_CONNECTED, /* not connected to IRC server */
	CMDERR_NOT_JOINED, /* not joined to any channels in this window */
	CMDERR_CHAN_NOT_FOUND, /* channel not found */
	CMDERR_CHAN_NOT_SYNCED, /* channel not fully synchronized yet */
	CMDERR_NOT_GOOD_IDEA /* not good idea to do, -yes overrides this */
};

/* Return the full command for `alias' */
#define alias_find(alias) \
	iconfig_get_str("aliases", alias, NULL)

/* Returning from command function with error */
#define cmd_return_error(a) \
	G_STMT_START { \
	  signal_emit("error command", 1, GINT_TO_POINTER(a)); \
	  signal_stop(); \
	  return; \
	} G_STMT_END

#define cmd_param_error(a) \
	G_STMT_START { \
	  cmd_params_free(free_arg); \
	  cmd_return_error(a); \
	} G_STMT_END

extern GSList *commands;
extern char *current_command; /* the command we're right now. */

/* Bind command to specified function. */
void command_bind_to(const char *module, int pos, const char *cmd,
		     const char *category, SIGNAL_FUNC func);
#define command_bind(a, b, c) command_bind_to(MODULE_NAME, 1, a, b, c)
#define command_bind_first(a, b, c) command_bind_to(MODULE_NAME, 0, a, b, c)
#define command_bind_last(a, b, c) command_bind_to(MODULE_NAME, 2, a, b, c)

void command_unbind(const char *cmd, SIGNAL_FUNC func);

/* Run subcommand, `cmd' contains the base command, first word in `data'
   contains the subcommand */
void command_runsub(const char *cmd, const char *data,
		    void *server, void *item);

COMMAND_REC *command_find(const char *cmd);
int command_have_sub(const char *command);

/* Specify options that command can accept. `options' contains list of
   options separated with space, each option can contain a special
   char in front of it:

   '!': no argument (default)
   '-': optional argument
   '+': argument required
   '@': optional numeric argument

   for example if options = "save -file +nick", you can use
   /command -save -file [<filename>] -nick <nickname>

   You can call this command multiple times for same command, options
   will be merged. If there's any conflicts with option types, the last
   call will override the previous */
#define iscmdtype(c) \
        ((c) == '!' || (c) == '-' || (c) == '+' || (c) == '@')
void command_set_options_module(const char *module,
				const char *cmd, const char *options);
#define command_set_options(cmd, options) \
	command_set_options_module(MODULE_NAME, cmd, options)

/* Returns TRUE if command has specified option. */
int command_have_option(const char *cmd, const char *option);

/* count can have these flags: */
#define PARAM_WITHOUT_FLAGS(a) ((a) & 0x00000fff)
/* don't check for quotes - "arg1 arg2" is NOT treated as one argument */
#define PARAM_FLAG_NOQUOTES 0x00001000
/* final argument gets all the rest of the arguments */
#define PARAM_FLAG_GETREST 0x00002000
/* command contains options - first you need to specify them with
   command_set_options() function. Example:

     -cmd requiredarg -noargcmd -cmd2 "another arg" -optnumarg rest of text

   You would call this with:

   // only once in init
   command_set_options("mycmd", "+cmd noargcmd -cmd2 @optnumarg");

   GHashTable *optlist;

   cmd_get_params(data, &free_me, 1 | PARAM_FLAG_OPTIONS |
                  PARAM_FLAG_GETREST, "mycmd", &optlist, &rest);

   The optlist hash table is filled:

   "cmd" = "requiredarg"
   "noargcmd" = ""
   "cmd2" = "another arg"
   "optnumarg" = "" - this is because "rest" isn't a numeric value
*/
#define PARAM_FLAG_OPTIONS 0x00004000
/* don't complain about unknown options */
#define PARAM_FLAG_UNKNOWN_OPTIONS 0x00008000
/* optional channel in first argument */
#define PARAM_FLAG_OPTCHAN 0x00010000

char *cmd_get_param(char **data);
/* get parameters from command - you should point free_me somewhere and
   cmd_params_free() it after you don't use any of the parameters anymore.

   Returns TRUE if all ok, FALSE if error occured. */
int cmd_get_params(const char *data, gpointer *free_me, int count, ...);

void cmd_params_free(void *free_me);

void commands_remove_module(const char *module);

void commands_init(void);
void commands_deinit(void);

#endif
