/*
 commands.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/window-item-def.h>

#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>

#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

GSList *commands;
char *current_command;

static int signal_default_command;

static GSList *alias_runstack;

COMMAND_REC *command_find(const char *cmd)
{
	GSList *tmp;

	g_return_val_if_fail(cmd != NULL, NULL);

	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->cmd, cmd) == 0)
			return rec;
	}

	return NULL;
}

static COMMAND_MODULE_REC *command_module_find(COMMAND_REC *rec,
					       const char *module)
{
	GSList *tmp;

	g_return_val_if_fail(rec != NULL, NULL);
	g_return_val_if_fail(module != NULL, NULL);

	for (tmp = rec->modules; tmp != NULL; tmp = tmp->next) {
		COMMAND_MODULE_REC *rec = tmp->data;

		if (g_ascii_strcasecmp(rec->name, module) == 0)
			return rec;
	}

	return NULL;
}

static COMMAND_MODULE_REC *
command_module_find_and_remove(COMMAND_REC *rec, SIGNAL_FUNC func)
{
	GSList *tmp, *tmp2;

	g_return_val_if_fail(rec != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	for (tmp = rec->modules; tmp != NULL; tmp = tmp->next) {
		COMMAND_MODULE_REC *rec = tmp->data;

		for (tmp2 = rec->callbacks; tmp2 != NULL; tmp2 = tmp2->next) {
			COMMAND_CALLBACK_REC *cb = tmp2->data;

			if (cb->func == func) {
				rec->callbacks =
					g_slist_remove(rec->callbacks, cb);
				g_free(cb);
				return rec;
			}
		}
	}

	return NULL;
}

int command_have_sub(const char *command)
{
	GSList *tmp;
	int len;

	g_return_val_if_fail(command != NULL, FALSE);

	/* find "command "s */
        len = strlen(command);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_ascii_strncasecmp(rec->cmd, command, len) == 0 &&
		    rec->cmd[len] == ' ')
			return TRUE;
	}

	return FALSE;
}

static COMMAND_MODULE_REC *
command_module_get(COMMAND_REC *rec, const char *module, int protocol)
{
        COMMAND_MODULE_REC *modrec;

	g_return_val_if_fail(rec != NULL, NULL);

	modrec = command_module_find(rec, module);
	if (modrec == NULL) {
		modrec = g_new0(COMMAND_MODULE_REC, 1);
		modrec->name = g_strdup(module);
                modrec->protocol = -1;
		rec->modules = g_slist_append(rec->modules, modrec);
	}

        if (protocol != -1)
		modrec->protocol = protocol;

        return modrec;
}

void command_bind_full(const char *module, int priority, const char *cmd,
		       int protocol, const char *category, SIGNAL_FUNC func,
		       void *user_data)
{
	COMMAND_REC *rec;
	COMMAND_MODULE_REC *modrec;
        COMMAND_CALLBACK_REC *cb;
	char *str;

	g_return_if_fail(module != NULL);
	g_return_if_fail(cmd != NULL);

	rec = command_find(cmd);
	if (rec == NULL) {
		rec = g_new0(COMMAND_REC, 1);
		rec->cmd = g_strdup(cmd);
		rec->category = category == NULL ? NULL : g_strdup(category);
		commands = g_slist_append(commands, rec);
	}
        modrec = command_module_get(rec, module, protocol);

	cb = g_new0(COMMAND_CALLBACK_REC, 1);
	cb->func = func;
	cb->user_data = user_data;
	modrec->callbacks = g_slist_append(modrec->callbacks, cb);

	if (func != NULL) {
		str = g_strconcat("command ", cmd, NULL);
		signal_add_full(module, priority, str, func, user_data);
		g_free(str);
	}

	signal_emit("commandlist new", 1, rec);
}

static void command_free(COMMAND_REC *rec)
{
	commands = g_slist_remove(commands, rec);
	signal_emit("commandlist remove", 1, rec);

	g_free_not_null(rec->category);
	g_strfreev(rec->options);
	g_free(rec->cmd);
	g_free(rec);
}

static void command_module_free(COMMAND_MODULE_REC *modrec, COMMAND_REC *rec)
{
	rec->modules = g_slist_remove(rec->modules, modrec);

	g_slist_foreach(modrec->callbacks, (GFunc) g_free, NULL);
	g_slist_free(modrec->callbacks);
        g_free(modrec->name);
        g_free_not_null(modrec->options);
        g_free(modrec);
}

static void command_module_destroy(COMMAND_REC *rec,
				   COMMAND_MODULE_REC *modrec)
{
	GSList *tmp, *freelist;

        command_module_free(modrec, rec);

	/* command_set_options() might have added module declaration of it's
	   own without any signals .. check if they're the only ones left
	   and if so, destroy them. */
        freelist = NULL;
	for (tmp = rec->modules; tmp != NULL; tmp = tmp->next) {
		COMMAND_MODULE_REC *rec = tmp->data;

		if (rec->callbacks == NULL)
			freelist = g_slist_append(freelist, rec);
		else {
                        g_slist_free(freelist);
                        freelist = NULL;
			break;
		}
	}

	g_slist_foreach(freelist, (GFunc) command_module_free, rec);
	g_slist_free(freelist);

	if (rec->modules == NULL)
		command_free(rec);
}

void command_unbind_full(const char *cmd, SIGNAL_FUNC func, void *user_data)
{
	COMMAND_REC *rec;
	COMMAND_MODULE_REC *modrec;
	char *str;

	g_return_if_fail(cmd != NULL);
	g_return_if_fail(func != NULL);

	rec = command_find(cmd);
	if (rec != NULL) {
		modrec = command_module_find_and_remove(rec, func);
		g_return_if_fail(modrec != NULL);

		if (modrec->callbacks == NULL)
			command_module_destroy(rec, modrec);
	}

	str = g_strconcat("command ", cmd, NULL);
	signal_remove_data(str, func, user_data);
	g_free(str);
}

/* Expand `cmd' - returns `cmd' if not found, NULL if more than one
   match is found */
static const char *command_expand(char *cmd)
{
	GSList *tmp;
	const char *match;
	int len, multiple;

	g_return_val_if_fail(cmd != NULL, NULL);

	multiple = FALSE;
	match = NULL;
	len = strlen(cmd);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_ascii_strncasecmp(rec->cmd, cmd, len) == 0 &&
		    strchr(rec->cmd+len, ' ') == NULL) {
			if (rec->cmd[len] == '\0') {
				/* full match */
				return rec->cmd;
			}

			if (match != NULL) {
				/* multiple matches, we still need to check
				   if there's some command left that is a
				   full match.. */
				multiple = TRUE;
			}

			/* check that this is the only match */
			match = rec->cmd;
		}
	}

	if (multiple) {
		signal_emit("error command", 2,
			    GINT_TO_POINTER(CMDERR_AMBIGUOUS), cmd);
		return NULL;
	}

	return match != NULL ? match : cmd;
}

void command_runsub(const char *cmd, const char *data,
		    void *server, void *item)
{
	const char *newcmd;
	char *orig, *subcmd, *defcmd, *args;

	g_return_if_fail(data != NULL);

        while (*data == ' ') data++;

	if (*data == '\0') {
                /* no subcommand given - list the subcommands */
		signal_emit("list subcommands", 1, cmd);
		return;
	}

	/* get command.. */
	orig = subcmd = g_strdup_printf("command %s %s", cmd, data);
	args = strchr(subcmd+8 + strlen(cmd)+1, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";
	while (*args == ' ') args++;

	/* check if this command can be expanded */
	newcmd = command_expand(subcmd+8);
	if (newcmd == NULL) {
                /* ambiguous command */
		g_free(orig);
		return;
	}

	subcmd = g_strconcat("command ", newcmd, NULL);

	ascii_strdown(subcmd);
	if (!signal_emit(subcmd, 3, args, server, item)) {
		defcmd = g_strdup_printf("default command %s", cmd);
		if (!signal_emit(defcmd, 3, data, server, item)) {
			signal_emit("error command", 2,
				    GINT_TO_POINTER(CMDERR_UNKNOWN), subcmd+8);
		}
                g_free(defcmd);
	}

	g_free(subcmd);
	g_free(orig);
}

static char *optname(char *option)
{
	char *opt = option;
	if (*opt == '~')
		opt++;
	if (iscmdtype(*opt))
		opt++;
	return opt;
}

static gboolean optflag(char *option, char *flag)
{
	if (*option == '~')
		return optflag(option + 1, flag);

	return (strchr(flag, *option) != NULL) || (!iscmdtype(*option) && strchr(flag, ' '));
}

static GSList *optlist_find(GSList *optlist, const char *option)
{
	while (optlist != NULL) {
		char *name = optname(optlist->data);

		if (g_ascii_strcasecmp(name, option) == 0)
			return optlist;

		optlist = optlist->next;
	}

	return NULL;
}

int command_have_option(const char *cmd, const char *option)
{
	COMMAND_REC *rec;
	char **tmp;

	g_return_val_if_fail(cmd != NULL, FALSE);
	g_return_val_if_fail(option != NULL, FALSE);

        rec = command_find(cmd);
	g_return_val_if_fail(rec != NULL, FALSE);

	if (rec->options == NULL)
		return FALSE;

	for (tmp = rec->options; *tmp != NULL; tmp++) {
		char *name = optname(*tmp);

		if (g_ascii_strcasecmp(name, option) == 0)
			return TRUE;
	}

	return FALSE;
}

static void command_calc_options(COMMAND_REC *rec, const char *options)
{
	char **optlist, **tmp, *name, *str;
	GSList *list, *oldopt;

	optlist = g_strsplit(options, " ", -1);

	if (rec->options == NULL) {
                /* first call - use specified args directly */
		rec->options = optlist;
		return;
	}

	/* save old options to linked list */
	list = NULL;
	for (tmp = rec->options; *tmp != NULL; tmp++)
                list = g_slist_append(list, g_strdup(*tmp));
	g_strfreev(rec->options);

	/* merge the options */
	for (tmp = optlist; *tmp != NULL; tmp++) {
		name = optname(*tmp);

		oldopt = optlist_find(list, name);
		if (oldopt != NULL) {
                        /* already specified - overwrite old definition */
			g_free(oldopt->data);
			oldopt->data = g_strdup(*tmp);
		} else {
			/* new option, append to list */
                        list = g_slist_append(list, g_strdup(*tmp));
		}
	}
	g_strfreev(optlist);

	/* linked list -> string[] */
	str = i_slist_to_string(list, " ");
	rec->options = g_strsplit(str, " ", -1);
        g_free(str);

        g_slist_foreach(list, (GFunc) g_free, NULL);
	g_slist_free(list);
}

/* recalculate options to command from options in all modules */
static void command_update_options(COMMAND_REC *rec)
{
	GSList *tmp;

	g_strfreev(rec->options);
	rec->options = NULL;

	for (tmp = rec->modules; tmp != NULL; tmp = tmp->next) {
		COMMAND_MODULE_REC *modrec = tmp->data;

		if (modrec->options != NULL)
			command_calc_options(rec, modrec->options);
	}
}

void command_set_options_module(const char *module,
				const char *cmd, const char *options)
{
	COMMAND_REC *rec;
	COMMAND_MODULE_REC *modrec;
        int reload;

	g_return_if_fail(module != NULL);
	g_return_if_fail(cmd != NULL);
	g_return_if_fail(options != NULL);

        rec = command_find(cmd);
	g_return_if_fail(rec != NULL);
        modrec = command_module_get(rec, module, -1);

	reload = modrec->options != NULL;
        if (reload) {
		/* options already set for the module ..
		   we need to recalculate everything */
		g_free(modrec->options);
	}

	modrec->options = g_strdup(options);

        if (reload)
		command_update_options(rec);
        else
		command_calc_options(rec, options);
}

char *cmd_get_param(char **data)
{
	char *pos;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(*data != NULL, NULL);

	while (**data == ' ') (*data)++;
	pos = *data;

	while (**data != '\0' && **data != ' ') (*data)++;
	if (**data == ' ') *(*data)++ = '\0';

	return pos;
}

char *cmd_get_quoted_param(char **data)
{
	char *pos, quote;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(*data != NULL, NULL);

	while (**data == ' ') (*data)++;
	if (**data != '\'' && **data != '"')
		return cmd_get_param(data);

	quote = **data; (*data)++;

	pos = *data;
	while (**data != '\0' && (**data != quote ||
				  ((*data)[1] != ' ' && (*data)[1] != '\0'))) {
		if (**data == '\\' && (*data)[1] != '\0')
                        memmove(*data, (*data)+1, strlen(*data));
		(*data)++;
	}

	if (**data == quote) {
		*(*data)++ = '\0';
		if (**data == ' ')
			(*data)++;
	}

	return pos;
}

/* Find specified option from list of options - the `option' might be
   shortened version of the full command. Returns index where the
   option was found, -1 if not found or -2 if there was multiple matches. */
static int option_find(char **array, const char *option)
{
	char **tmp;
	int index, found, len, multiple;

	g_return_val_if_fail(array != NULL, -1);
	g_return_val_if_fail(option != NULL, -1);

	len = strlen(option);

	found = -1; index = 0; multiple = FALSE;
	for (tmp = array; *tmp != NULL; tmp++, index++) {
		const char *text = optname(*tmp);

		if (g_ascii_strncasecmp(text, option, len) == 0) {
			if (text[len] == '\0') {
				/* full match */
				return index;
			}

			if (found != -1) {
				/* multiple matches - we still need to check
				   if there's a full match left.. */
				multiple = TRUE;
			}

			/* partial match, check that it's the only one */
			found = index;
		}
	}

	if (multiple)
		return -2;

	return found;
}

static int get_cmd_options(char **data, int ignore_unknown,
			   const char *cmd, GHashTable *options)
{
	COMMAND_REC *rec;
	char *option, *arg, **optlist;
	int pos;

	/* get option definitions */
	rec = cmd == NULL ? NULL : command_find(cmd);
	optlist = rec == NULL ? NULL : rec->options;

	option = NULL; pos = -1;
	for (;;) {
		if (**data == '\0' || **data == '-') {
			if (option != NULL && optflag(optlist[pos], "+")) {
				/* required argument missing! */
				*data = optname(optlist[pos]);
				return CMDERR_OPTION_ARG_MISSING;
			}
		}
		if (**data == '-') {
			(*data)++;
			if (**data == '-' && (*data)[1] == ' ') {
				/* -- option means end of options even
				   if next word starts with - */
				(*data)++;
				while (**data == ' ') (*data)++;
				break;
			}

			if (**data == '\0')
				option = "-";
			else if (**data != ' ')
				option = cmd_get_param(data);
			else {
				option = "-";
				(*data)++;
			}

			/* check if this option can have argument */
			pos = optlist == NULL ? -1 :
				option_find(optlist, option);

			if (pos == -1 && optlist != NULL &&
			    is_numeric(option, '\0')) {
				/* check if we want -<number> option */
				pos = option_find(optlist, "#");
				if (pos != -1) {
					g_hash_table_insert(options, "#",
							    option);
                                        pos = -3;
				}
			}

			if (pos == -1 && !ignore_unknown) {
				/* unknown option! */
                                *data = option;
				return CMDERR_OPTION_UNKNOWN;
			}
			if (pos == -2 && !ignore_unknown) {
                                /* multiple matches */
				*data = option;
				return CMDERR_OPTION_AMBIGUOUS;
			}
			if (pos >= 0) {
				/* if we used a shortcut of parameter, put
				   the whole parameter name in options table */
				option = optname(optlist[pos]);
			}
			if (options != NULL && pos != -3)
				g_hash_table_insert(options, option, "");

			if (pos < 0 || optflag(optlist[pos], " !"))
				option = NULL;

			while (**data == ' ') (*data)++;
			continue;
		}

		if (option == NULL)
			break;

		if (optflag(optlist[pos], "@") && !is_numeric(*data, ' '))
			break; /* expected a numeric argument */

		/* save the argument */
		arg = cmd_get_quoted_param(data);
		if (options != NULL) {
			g_hash_table_remove(options, option);
			g_hash_table_insert(options, option, arg);
		}
		option = NULL;

		while (**data == ' ') (*data)++;
	}

	return 0;
}

typedef struct {
	char *data;
        GHashTable *options;
} CMD_TEMP_REC;

static const char *
get_optional_channel(WI_ITEM_REC *active_item, char **data, int require_name)
{
        CHANNEL_REC *chanrec;
	const char *ret;
	char *tmp, *origtmp, *channel;

	if (active_item == NULL || active_item->server == NULL) {
                /* no active channel in window, channel required */
		return cmd_get_param(data);
	}

	origtmp = tmp = g_strdup(*data);
	channel = cmd_get_param(&tmp);

	if (g_strcmp0(channel, "*") == 0 && IS_CHANNEL(active_item) &&
	    !require_name) {
                /* "*" means active channel */
		cmd_get_param(data);
		ret = window_item_get_target(active_item);
	} else if (IS_CHANNEL(active_item) &&
		   !server_ischannel(active_item->server, channel)) {
                /* we don't have channel parameter - use active channel */
		ret = window_item_get_target(active_item);
	} else {
		/* Find the channel first and use it's name if found.
		   This allows automatic !channel -> !XXXXXchannel replaces. */
                channel = cmd_get_param(data);

		chanrec = channel_find(active_item->server, channel);
		ret = chanrec == NULL ? channel : chanrec->name;
	}

	g_free(origtmp);
        return ret;
}

int cmd_get_params(const char *data, gpointer *free_me, int count, ...)
{
        WI_ITEM_REC *item;
	CMD_TEMP_REC *rec;
	GHashTable **opthash;
	char **str, *arg, *datad;
	va_list args;
	int cnt, error, ignore_unknown, require_name;

	g_return_val_if_fail(data != NULL, FALSE);

	va_start(args, count);

	rec = g_new0(CMD_TEMP_REC, 1);
	rec->data = g_strdup(data);
	*free_me = rec;

        datad = rec->data;
	error = FALSE;

	item = (count & PARAM_FLAG_OPTCHAN) == 0 ? NULL:
		(WI_ITEM_REC *) va_arg(args, WI_ITEM_REC *);

	if (count & PARAM_FLAG_OPTIONS) {
		arg = (char *) va_arg(args, char *);
		opthash = (GHashTable **) va_arg(args, GHashTable **);

		rec->options = *opthash =
		    g_hash_table_new((GHashFunc) i_istr_hash, (GCompareFunc) i_istr_equal);

		ignore_unknown = count & PARAM_FLAG_UNKNOWN_OPTIONS;
		error = get_cmd_options(&datad, ignore_unknown,
					arg, *opthash);
	}

	if (!error) {
		/* and now handle the string */
		cnt = PARAM_WITHOUT_FLAGS(count);
		if (count & PARAM_FLAG_OPTCHAN) {
			/* optional channel as first parameter */
			require_name = (count & PARAM_FLAG_OPTCHAN_NAME) ==
				PARAM_FLAG_OPTCHAN_NAME;
			arg = (char *) get_optional_channel(item, &datad, require_name);

			str = (char **) va_arg(args, char **);
			if (str != NULL) *str = arg;
			cnt--;
		}

		while (cnt-- > 0) {
			if (cnt == 0 && count & PARAM_FLAG_GETREST) {
				/* get rest */
				arg = datad;

				/* strip the trailing whitespace */
				if (count & PARAM_FLAG_STRIP_TRAILING_WS) {
					arg = g_strchomp(arg);
				}
			} else {
				arg = (count & PARAM_FLAG_NOQUOTES) ?
					cmd_get_param(&datad) :
					cmd_get_quoted_param(&datad);
			}

			str = (char **) va_arg(args, char **);
			if (str != NULL) *str = arg;
		}
	}
	va_end(args);

	if (error) {
                signal_emit("error command", 2, GINT_TO_POINTER(error), datad);
		signal_stop();

                cmd_params_free(rec);
		*free_me = NULL;
	}

	return !error;
}

void cmd_params_free(void *free_me)
{
	CMD_TEMP_REC *rec = free_me;

	if (rec->options != NULL) g_hash_table_destroy(rec->options);
	g_free(rec->data);
	g_free(rec);
}

static void command_module_unbind_all(COMMAND_REC *rec,
				      COMMAND_MODULE_REC *modrec)
{
	GSList *tmp, *next;

	for (tmp = modrec->callbacks; tmp != NULL; tmp = next) {
		COMMAND_CALLBACK_REC *cb = tmp->data;
		next = tmp->next;

		command_unbind_full(rec->cmd, cb->func, cb->user_data);
	}

	if (g_slist_find(commands, rec) != NULL) {
		/* this module might have removed some options
		   from command, update them. */
		command_update_options(rec);
	}
}

void commands_remove_module(const char *module)
{
	GSList *tmp, *next, *modlist;

	g_return_if_fail(module != NULL);

	for (tmp = commands; tmp != NULL; tmp = next) {
		COMMAND_REC *rec = tmp->data;

                next = tmp->next;
		modlist = i_slist_find_string(rec->modules, module);
		if (modlist != NULL)
			command_module_unbind_all(rec, modlist->data);
	}
}

static int cmd_protocol_match(COMMAND_REC *cmd, SERVER_REC *server)
{
	GSList *tmp;

	for (tmp = cmd->modules; tmp != NULL; tmp = tmp->next) {
		COMMAND_MODULE_REC *rec = tmp->data;

		if (rec->protocol == -1) {
			/* at least one module accepts the command
			   without specific protocol */
			return 1;
		}

		if (server != NULL && rec->protocol == server->chat_type) {
                        /* matching protocol found */
                        return 1;
		}
	}

        return 0;
}

#define alias_runstack_push(alias) \
	alias_runstack = g_slist_append(alias_runstack, alias)

#define alias_runstack_pop(alias) \
	alias_runstack = g_slist_remove(alias_runstack, alias)

#define alias_runstack_find(alias) (i_slist_find_icase_string(alias_runstack, alias) != NULL)

static void parse_command(const char *command, int expand_aliases,
			  SERVER_REC *server, void *item)
{
        COMMAND_REC *rec;
	const char *alias, *newcmd;
	char *cmd, *orig, *args, *oldcmd;

	g_return_if_fail(command != NULL);

	cmd = orig = g_strconcat("command ", command, NULL);
	args = strchr(cmd+8, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	/* check if there's an alias for command. Don't allow
	   recursive aliases */
	alias = !expand_aliases || alias_runstack_find(cmd+8) ? NULL :
		alias_find(cmd+8);
	if (alias != NULL) {
                alias_runstack_push(cmd+8);
		eval_special_string(alias, args, server, item);
                alias_runstack_pop(cmd+8);
		g_free(orig);
		return;
	}

	/* check if this command can be expanded */
	newcmd = command_expand(cmd+8);
	if (newcmd == NULL) {
                /* ambiguous command */
		g_free(orig);
		return;
	}

	rec = command_find(newcmd);
	if (rec != NULL && !cmd_protocol_match(rec, server)) {
		g_free(orig);

		signal_emit("error command", 1,
			    GINT_TO_POINTER(server == NULL ?
					    CMDERR_NOT_CONNECTED :
					    CMDERR_ILLEGAL_PROTO));
		return;
	}

	cmd = g_strconcat("command ", newcmd, NULL);
	ascii_strdown(cmd);

	oldcmd = current_command;
	current_command = cmd+8;
        if (server != NULL) server_ref(server);
        if (!signal_emit(cmd, 3, args, server, item)) {
		signal_emit_id(signal_default_command, 3,
			       command, server, item);
	}
	if (server != NULL) {
		if (server->connection_lost)
			server_disconnect(server);
		server_unref(server);
	}
	current_command = oldcmd;

	g_free(cmd);
	g_free(orig);
}

static void event_command(const char *line, SERVER_REC *server, void *item)
{
	char *cmdchar;
	int expand_aliases = TRUE;

	g_return_if_fail(line != NULL);

	cmdchar = *line == '\0' ? NULL :
		strchr(settings_get_str("cmdchars"), *line);
	if (cmdchar != NULL && line[1] == ' ') {
		/* "/ text" = same as sending "text" to active channel. */
		line += 2;
		cmdchar = NULL;
	}
	if (cmdchar == NULL) {
		/* non-command - let someone else handle this */
		signal_emit("send text", 3, line, server, item);
		return;
	}

	/* same cmdchar twice ignores aliases */
	line++;
	if (*line == *cmdchar) {
		line++;
		expand_aliases = FALSE;
	}

	/* ^command hides the output - we'll do this at fe-common but
	   we have to skip the ^ char here.. */
	if (*line == '^') line++;

	parse_command(line, expand_aliases, server, item);
}

static int eval_recursion_depth=0;
/* SYNTAX: EVAL <command(s)> */
static void cmd_eval(const char *data, SERVER_REC *server, void *item)
{
	g_return_if_fail(data != NULL);
	if (eval_recursion_depth > 100)
		cmd_return_error(CMDERR_EVAL_MAX_RECURSE);


	eval_recursion_depth++;
	eval_special_string(data, "", server, item);
	eval_recursion_depth--;
}

/* SYNTAX: CD <directory> */
static void cmd_cd(const char *data)
{
	char *str;

	g_return_if_fail(data != NULL);
	if (*data == '\0') return;

	str = convert_home(data);
	if (chdir(str) != 0) {
		g_warning("Failed to chdir(): %s", strerror(errno));
	}
	g_free(str);
}

void commands_init(void)
{
	commands = NULL;
	current_command = NULL;
	alias_runstack = NULL;

	signal_default_command = signal_get_uniq_id("default command");

	settings_add_str("misc", "cmdchars", "/");
	signal_add("send command", (SIGNAL_FUNC) event_command);

	command_bind("eval", NULL, (SIGNAL_FUNC) cmd_eval);
	command_bind("cd", NULL, (SIGNAL_FUNC) cmd_cd);
}

void commands_deinit(void)
{
	g_free_not_null(current_command);

	signal_remove("send command", (SIGNAL_FUNC) event_command);

	command_unbind("eval", (SIGNAL_FUNC) cmd_eval);
	command_unbind("cd", (SIGNAL_FUNC) cmd_cd);
}
