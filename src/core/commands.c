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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "server.h"
#include "server-redirect.h"
#include "special-vars.h"

#include "lib-config/iconfig.h"
#include "settings.h"

GSList *commands;
char *current_command;

static GSList *cmdget_funcs;
static int signal_default_command;

COMMAND_REC *command_find(const char *cmd)
{
	GSList *tmp;

	g_return_val_if_fail(cmd != NULL, NULL);

	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_strcasecmp(rec->cmd, cmd) == 0)
			return rec;
	}

	return NULL;
}

void command_bind_to(int pos, const char *cmd, const char *category, SIGNAL_FUNC func)
{
	COMMAND_REC *rec;
	char *str;

	g_return_if_fail(cmd != NULL);

	rec = command_find(cmd);
	if (rec == NULL) {
		rec = g_new0(COMMAND_REC, 1);
		rec->cmd = g_strdup(cmd);
		rec->category = category == NULL ? NULL : g_strdup(category);
		commands = g_slist_append(commands, rec);
	}
	rec->count++;

	if (func != NULL) {
		str = g_strconcat("command ", cmd, NULL);
		signal_add_to(MODULE_NAME, pos, str, func);
		g_free(str);
	}

	signal_emit("commandlist new", 1, rec);
}

void command_free(COMMAND_REC *rec)
{
	commands = g_slist_remove(commands, rec);
	signal_emit("commandlist remove", 1, rec);

	g_free_not_null(rec->category);
	g_strfreev(rec->options);
	g_free(rec->cmd);
	g_free(rec);
}

void command_unbind(const char *cmd, SIGNAL_FUNC func)
{
	COMMAND_REC *rec;
	char *str;

	g_return_if_fail(cmd != NULL);

	rec = command_find(cmd);
	if (rec != NULL && --rec->count == 0)
		command_free(rec);

	if (func != NULL) {
		str = g_strconcat("command ", cmd, NULL);
		signal_remove(str, func);
		g_free(str);
	}
}

/* Expand `cmd' - returns `cmd' if not found, NULL if more than one
   match is found */
static const char *command_expand(char *cmd)
{
	GSList *tmp;
	const char *match;
	int len;

	g_return_val_if_fail(cmd != NULL, NULL);

	match = NULL;
	len = strlen(cmd);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_strncasecmp(rec->cmd, cmd, len) == 0 &&
		    strchr(rec->cmd+len, ' ') == NULL) {
			if (match != NULL) {
                                /* multiple matches */
				signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_AMBIGUOUS), cmd);
				return NULL;
			}

			if (rec->cmd[len] == '\0') {
				/* full match */
				return rec->cmd;
			}

			/* check that this is the only match */
			match = rec->cmd;
		}
	}

	return match != NULL ? match : cmd;
}

void command_runsub(const char *cmd, const char *data, void *server, void *item)
{
	const char *newcmd;
	char *orig, *subcmd, *defcmd, *args;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
                /* no subcommand given - unknown command? */
		signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_UNKNOWN), cmd);
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

	g_strdown(subcmd);
	if (!signal_emit(subcmd, 3, args, server, item)) {
		defcmd = g_strdup_printf("default command %s", cmd);
		if (!signal_emit(defcmd, 3, data, server, item))
			signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_UNKNOWN), subcmd+8);
                g_free(defcmd);
	}

	g_free(subcmd);
	g_free(orig);
}

static GSList *optlist_find(GSList *optlist, const char *option)
{
	while (optlist != NULL) {
		char *name = optlist->data;
		if (iscmdtype(*name)) name++;

		if (g_strcasecmp(name, option) == 0)
			return optlist;

		optlist = optlist->next;
	}

	return NULL;
}

void command_set_options(const char *cmd, const char *options)
{
	COMMAND_REC *rec;
	char **optlist, **tmp, *name, *str;
	GSList *list, *oldopt;

	g_return_if_fail(cmd != NULL);
	g_return_if_fail(options != NULL);

        rec = command_find(cmd);
	g_return_if_fail(rec != NULL);

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
		name = iscmdtype(**tmp) ? (*tmp)+1 : *tmp;

		oldopt = optlist_find(list, name);
		if (oldopt != NULL) {
                        /* already specified - overwrite old defination */
			g_free(oldopt->data);
			oldopt->data = g_strdup(*tmp);
		} else {
			/* new option, append to list */
                        list = g_slist_append(list, g_strdup(*tmp));
		}
	}
	g_strfreev(optlist);

	/* linked list -> string[] */
        g_free(rec->options);
	str = gslist_to_string(list, " ");
	rec->options = g_strsplit(str, " ", -1);
        g_free(str);

        g_slist_foreach(list, (GFunc) g_free, NULL);
	g_slist_free(list);
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

static char *cmd_get_quoted_param(char **data)
{
	char *pos, quote;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(*data != NULL, NULL);

	while (**data == ' ') (*data)++;
	if (**data != '\'' && **data != '"')
		return cmd_get_param(data);

	quote = **data; (*data)++;

	pos = *data;
	while (**data != '\0' && **data != quote) {
		if (**data == '\\' && (*data)[1] != '\0')
                        g_memmove(*data, (*data)+1, strlen(*data));
		(*data)++;
	}

	if (**data != '\0') *(*data)++ = '\0';

	return pos;
}

/* Find specified option from list of options - the `option' might be
   shortened version of the full command. Returns index where the
   option was found, -1 if not found or -2 if there was multiple matches. */
static int option_find(char **array, const char *option)
{
	char **tmp;
	int index, found, len;

	g_return_val_if_fail(array != NULL, -1);
	g_return_val_if_fail(option != NULL, -1);

	len = strlen(option);
	g_return_val_if_fail(len > 0, -1);

	found = -1; index = 0;
	for (tmp = array; *tmp != NULL; tmp++, index++) {
		const char *text = *tmp + iscmdtype(**tmp);

		if (g_strncasecmp(text, option, len) == 0) {
			if (text[len] == '\0') {
				/* full match */
				return index;
			}

			if (found != -1) {
				/* multiple matches - abort */
				return -2;
			}

			/* partial match, check that it's the only one */
			found = index;
		}
	}

	return found;
}

static int get_cmd_options(char **data, int ignore_unknown,
			   const char *cmd, GHashTable *options)
{
	COMMAND_REC *rec;
	char *option, *arg, **optlist;
	int pos;

	/* get option definations */
	rec = cmd == NULL ? NULL : command_find(cmd);
	optlist = rec == NULL ? NULL : rec->options;

	option = NULL; pos = -1;
	for (;;) {
		if (**data == '-') {
			if (option != NULL && *optlist[pos] == '+') {
				/* required argument missing! */
                                *data = optlist[pos] + 1;
				return CMDERR_OPTION_ARG_MISSING;
			}

			(*data)++;
			if (**data == '-') {
				/* -- option means end of options even
				   if next word starts with - */
				(*data)++;
				while (isspace(**data)) (*data)++;
				break;
			}

			option = cmd_get_param(data);

			/* check if this option can have argument */
			pos = optlist == NULL ? -1 : option_find(optlist, option);
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
				option = optlist[pos] + iscmdtype(*optlist[pos]);
			}
			if (options != NULL) g_hash_table_insert(options, option, "");

			if (pos == -1 || !iscmdtype(*optlist[pos]))
				option = NULL;

			while (isspace(**data)) (*data)++;
			continue;
		}

		if (option == NULL)
			break;

		if (*optlist[pos] == '@' && !isdigit(**data))
			break; /* expected a numeric argument */

		/* save the argument */
		arg = cmd_get_quoted_param(data);
		if (options != NULL) {
			g_hash_table_remove(options, option);
			g_hash_table_insert(options, option, arg);
		}
		option = NULL;

		while (isspace(**data)) (*data)++;
	}

	return 0;
}

char *cmd_get_callfuncs(const char *data, int *count, va_list *args)
{
	CMD_GET_FUNC func;
	GSList *tmp;
	char *ret, *old;

	ret = g_strdup(data);
	for (tmp = cmdget_funcs; tmp != NULL; tmp = tmp->next) {
		func = (CMD_GET_FUNC) tmp->data;

		old = ret;
		ret = func(ret, count, args);
                g_free(old);
	}

	return ret;
}

typedef struct {
	char *data;
        GHashTable *options;
} CMD_TEMP_REC;

int cmd_get_params(const char *data, gpointer *free_me, int count, ...)
{
	CMD_TEMP_REC *rec;
	GHashTable **opthash;
	char **str, *arg, *datad, *old;
	va_list args;
	int cnt, error, len;

	g_return_val_if_fail(data != NULL, FALSE);

	va_start(args, count);

	/* get the length of the options in string */
	if ((count & PARAM_FLAG_OPTIONS) == 0)
		len = 0;
	else {
		old = datad = g_strdup(data);
		get_cmd_options(&datad, TRUE, NULL, NULL);
		len = (int) (datad-old);
		g_free(old);
	}

	/* send the text to custom functions to handle - skip options */
	old = datad = cmd_get_callfuncs(data+len, &count, &args);

	if (len > 0) {
		/* put the options + the new data to one string */
		datad = g_malloc(len+1 + strlen(old)+1);
		memcpy(datad, data, len);
		datad[len] = ' ';
		memcpy(datad+len+1, old, strlen(old)+1);
		g_free(old);

		old = datad;
	}

	rec = g_new0(CMD_TEMP_REC, 1);
	rec->data = old;
	*free_me = rec;

	/* and now handle the string */
	error = FALSE;
	cnt = PARAM_WITHOUT_FLAGS(count);
	while (cnt-- > 0) {
		if (count & PARAM_FLAG_OPTIONS) {
			arg = (char *) va_arg(args, char *);
			opthash = (GHashTable **) va_arg(args, GHashTable **);

			rec->options = *opthash = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
			error = get_cmd_options(&datad, count & PARAM_FLAG_UNKNOWN_OPTIONS, arg, *opthash);
			if (error) break;

			count &= ~PARAM_FLAG_OPTIONS;
			cnt++;
			continue;
		} else if (cnt == 0 && count & PARAM_FLAG_GETREST) {
			/* get rest */
			arg = datad;
		} else {
			arg = (count & PARAM_FLAG_NOQUOTES) ?
				cmd_get_param(&datad) :
				cmd_get_quoted_param(&datad);
		}

		str = (char **) va_arg(args, char **);
		if (str != NULL) *str = arg;
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

void cmd_get_add_func(CMD_GET_FUNC func)
{
        cmdget_funcs = g_slist_prepend(cmdget_funcs, (void *) func);
}

void cmd_get_remove_func(CMD_GET_FUNC func)
{
        cmdget_funcs = g_slist_prepend(cmdget_funcs, (void *) func);
}

static void parse_command(const char *command, int expand_aliases, SERVER_REC *server, void *item)
{
	const char *alias, *newcmd;
	char *cmd, *orig, *args, *oldcmd;

	cmd = orig = g_strconcat("command ", command, NULL);
	args = strchr(cmd+8, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	/* check if there's an alias for command */
	alias = expand_aliases ? alias_find(cmd+8) : NULL;
	if (alias != NULL) {
		eval_special_string(alias, args, server, item);
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

	cmd = g_strconcat("command ", newcmd, NULL);
	if (server != NULL)
		server_redirect_default((SERVER_REC *) server, cmd);

	g_strdown(cmd);
	oldcmd = current_command;
	current_command = cmd+8;
	if (!signal_emit(cmd, 3, args, server, item))
		signal_emit_id(signal_default_command, 3, command, server, item);
	current_command = oldcmd;

	g_free(cmd);
	g_free(orig);
}

static void event_command(const char *line, SERVER_REC *server, void *item)
{
	char *cmdchar;
	int expand_aliases = TRUE;

	g_return_if_fail(line != NULL);

	if (*line == '\0') {
		/* empty line, forget it. */
                signal_stop();
		return;
	}

	cmdchar = strchr(settings_get_str("cmdchars"), *line);
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

	/* same cmdchar twice ignores aliases ignores aliases */
	line++;
	if (*line == *cmdchar) {
		line++;
		expand_aliases = FALSE;
	}

	parse_command(line, expand_aliases, server, item);
}

static void cmd_eval(const char *data, SERVER_REC *server, void *item)
{
	g_return_if_fail(data != NULL);

	eval_special_string(data, "", server, item);
}

static void cmd_cd(const char *data)
{
	char *str;

	g_return_if_fail(data != NULL);
	if (*data == '\0') return;

	str = convert_home(data);
	chdir(str);
	g_free(str);
}

static void cmd_reload(const char *data)
{
	char *fname;

	fname = *data != '\0' ? g_strdup(data) :
		g_strdup_printf("%s/.irssi/config", g_get_home_dir());
        settings_reread(fname);
	g_free(fname);
}

static void cmd_save(const char *data)
{
	settings_save(*data != '\0' ? data : NULL);
}

void commands_init(void)
{
	commands = NULL;
	cmdget_funcs = NULL;
	current_command = NULL;

	signal_default_command = signal_get_uniq_id("default command");

	settings_add_str("misc", "cmdchars", "/");
	signal_add("send command", (SIGNAL_FUNC) event_command);

	command_bind("eval", NULL, (SIGNAL_FUNC) cmd_eval);
	command_bind("cd", NULL, (SIGNAL_FUNC) cmd_cd);
	command_bind("reload", NULL, (SIGNAL_FUNC) cmd_reload);
	command_bind("save", NULL, (SIGNAL_FUNC) cmd_save);
}

void commands_deinit(void)
{
	g_free_not_null(current_command);
	g_slist_free(cmdget_funcs);

	signal_remove("send command", (SIGNAL_FUNC) event_command);

	command_unbind("eval", (SIGNAL_FUNC) cmd_eval);
	command_unbind("cd", (SIGNAL_FUNC) cmd_cd);
	command_unbind("reload", (SIGNAL_FUNC) cmd_reload);
	command_unbind("save", (SIGNAL_FUNC) cmd_save);
}
