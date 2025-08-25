#ifndef IRSSI_CORE_COMMANDS_H
#define IRSSI_CORE_COMMANDS_H

#include <irssi/src/core/signals.h>

typedef struct {
	SIGNAL_FUNC func;
	void *user_data;
} COMMAND_CALLBACK_REC;

typedef struct {
	char *name;
	char *options;
        int protocol; /* chat protocol required for this command */
        GSList *callbacks;
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
	CMDERR_NOT_CONNECTED, /* not connected to server */
	CMDERR_NOT_JOINED, /* not joined to any channels in this window */
	CMDERR_CHAN_NOT_FOUND, /* channel not found */
	CMDERR_CHAN_NOT_SYNCED, /* channel not fully synchronized yet */
	CMDERR_ILLEGAL_PROTO, /* requires different chat protocol than the active server */
	CMDERR_NOT_GOOD_IDEA, /* not good idea to do, -yes overrides this */
	CMDERR_INVALID_TIME, /* invalid time specification */
	CMDERR_INVALID_CHARSET, /* invalid charset specification */
	CMDERR_EVAL_MAX_RECURSE, /* eval hit recursion limit */
	CMDERR_PROGRAM_NOT_FOUND, /* program not found */
	CMDERR_NO_SERVER_DEFINED, /* no server has been defined for a given chatnet */
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
void command_bind_full(const char *module, int priority, const char *cmd,
		       int protocol, const char *category, SIGNAL_FUNC func,
		       void *user_data);
#define command_bind(a, b, c) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_DEFAULT, a, -1, b, c, NULL)
#define command_bind_first(a, b, c) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_HIGH, a, -1, b, c, NULL)
#define command_bind_last(a, b, c) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_LOW, a, -1, b, c, NULL)

#define command_bind_data(a, b, c, d) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_DEFAULT, a, -1, b, c, d)
#define command_bind_data_first(a, b, c, d) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_HIGH, a, -1, b, c, d)
#define command_bind_data_last(a, b, c, d) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_LOW, a, -1, b, c, d)

#define command_bind_proto(a, b, c, d) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_DEFAULT, a, b, c, d, NULL)
#define command_bind_proto_first(a, b, c, d) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_HIGH, a, b, c, d, NULL)
#define command_bind_proto_last(a, b, c, d) command_bind_full(MODULE_NAME, SIGNAL_PRIORITY_LOW, a, b, c, d, NULL)

void command_unbind_full(const char *cmd, SIGNAL_FUNC func, void *user_data);
#define command_unbind(cmd, func) command_unbind_full(cmd, func, NULL)

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
/* optional channel in first argument, but don't treat "*" as current channel */
#define PARAM_FLAG_OPTCHAN_NAME (0x00020000|PARAM_FLAG_OPTCHAN)
/* strip the trailing whitespace */
#define PARAM_FLAG_STRIP_TRAILING_WS 0x00040000

char *cmd_get_param(char **data);
char *cmd_get_quoted_param(char **data);
/* get parameters from command - you should point free_me somewhere and
   cmd_params_free() it after you don't use any of the parameters anymore.

   Returns TRUE if all ok, FALSE if error occurred. */
int cmd_get_params(const char *data, gpointer *free_me, int count, ...);

void cmd_params_free(void *free_me);

void commands_remove_module(const char *module);

void commands_init(void);
void commands_deinit(void);

#endif
