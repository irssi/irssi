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

#define alias_find(alias) \
	iconfig_get_str("aliases", alias, NULL)

GSList *commands;
char *current_command;

static GSList *cmdget_funcs;
static int signal_default_command;

void command_bind(const char *cmd, const char *category, SIGNAL_FUNC func)
{
	COMMAND_REC *rec;
	char *str;

	g_return_if_fail(cmd != NULL);

	rec = g_new0(COMMAND_REC, 1);
	rec->cmd = g_strdup(cmd);
	rec->category = category == NULL ? NULL : g_strdup(category);
	commands = g_slist_append(commands, rec);

	if (func != NULL) {
		str = g_strconcat("command ", cmd, NULL);
		signal_add(str, func);
		g_free(str);
	}

	signal_emit("commandlist new", 1, rec);
}

void command_free(COMMAND_REC *rec)
{
	commands = g_slist_remove(commands, rec);
	signal_emit("commandlist remove", 1, rec);

	g_free_not_null(rec->category);
	g_free(rec->cmd);
	g_free(rec);
}

void command_unbind(const char *cmd, SIGNAL_FUNC func)
{
	GSList *tmp;
	char *str;

	g_return_if_fail(cmd != NULL);

	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_strcasecmp(rec->cmd, cmd) == 0) {
			command_free(rec);
			break;
		}
	}

	if (func != NULL) {
		str = g_strconcat("command ", cmd, NULL);
		signal_remove(str, func);
		g_free(str);
	}
}

void command_runsub(const char *cmd, const char *data, void *p1, void *p2)
{
	char *subcmd, *defcmd, *args;

	g_return_if_fail(data != NULL);

	/* get command.. */
	subcmd = g_strdup_printf("command %s %s", cmd, data);
	args = strchr(subcmd+9 + strlen(cmd), ' ');
	if (args != NULL) *args++ = '\0'; else args = "";
	while (*args == ' ') args++;

	g_strdown(subcmd);
	if (!signal_emit(subcmd, 3, args, p1, p2)) {
		defcmd = g_strdup_printf("default command %s", cmd);
		if (!signal_emit(defcmd, 3, data, p1, p2))
			signal_emit("unknown command", 3, strchr(subcmd, ' ')+1, p1, p2);
                g_free(defcmd);
	}
	g_free(subcmd);
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
	while (**data != '\0' && **data != quote) {
		if (**data == '\\' && (*data)[1] != '\0')
                        g_memmove(*data, (*data)+1, strlen(*data));
		(*data)++;
	}

	if (**data != '\0') *(*data)++ = '\0';

	return pos;
}

static char *get_opt_args(char **data)
{
	/* -cmd1 -cmd2 -cmd3 ... */
	char *p, *ret;

	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(*data != NULL, NULL);

	ret = NULL;
	for (p = *data;;) {
		if (*p != '-') {
			if (p == *data) return "";

			while (isspace(p[-1]) && p > *data) p--;
			if (*p != '\0') *p++ = '\0';
			ret = *data;
			*data = p;
			return ret;
		}

		while (!isspace(*p) && *p != '\0') p++;
		while (isspace(*p)) p++;
	}
}

static void cmd_params_pack(char ***subargs, char *end, char *start, char *newstart)
{
	char ***tmp;
	char *data;
	int bufsize, datalen, len;

	bufsize = (int) (end-newstart)+1;

	data = g_malloc(bufsize); datalen = 0;
	for (tmp = subargs; *tmp != NULL; tmp++) {
		if (**tmp < start || **tmp > end)
			continue;

                len = strlen(**tmp)+1;
		if (datalen+len > bufsize)
			g_error("cmd_params_pack() : buffer overflow!");

		memcpy(data+datalen, **tmp, len);
		**tmp = newstart+datalen;
		datalen += len;
	}

	g_memmove(newstart, data, datalen);
	g_free(data);
}

int arg_find(char **array, const char *item)
{
	char **tmp;
	int index;

	g_return_val_if_fail(array != NULL, 0);
	g_return_val_if_fail(item != NULL, 0);

	index = 0;
	for (tmp = array; *tmp != NULL; tmp++, index++) {
		if (g_strcasecmp(*tmp + (**tmp == '@'), item) == 0)
			return index;
	}

	return -1;
}

static int get_multi_args(char **data, va_list va)
{
	/* -cmd1 arg1 -cmd2 "argument two" -cmd3 */
        GString *returnargs;
	char **args, **arglist, *arg, *origdata;
	char **nextarg, ***subargs;
	int eat, pos;

	eat = 0;
	args = (char **) va_arg(va, char **);
	g_return_val_if_fail(args != NULL && *args != NULL && **args != '\0', 0);

	arglist = g_strsplit(*args, " ", -1);
	eat = strarray_length(arglist);

	subargs = g_new(char **, eat+1);
	for (pos = 0; pos < eat; pos++) {
		subargs[pos] = (char **) va_arg(va, char **);
		if (subargs[pos] == NULL) {
			g_free(subargs);
			g_warning("get_multi_args() : subargument == NULL");
			return eat;
		}
		*subargs[pos] = "";
	}
	subargs[eat] = NULL;

        origdata = *data;
	returnargs = g_string_new(NULL);
	nextarg = NULL;
	for (;;) {
		if (**data == '-') {
			(*data)++; arg = cmd_get_param(data);
			g_string_sprintfa(returnargs, "-%s ", arg);

			/* check if this argument can have parameter */
			pos = arg_find(arglist, arg);
			nextarg = pos == -1 ? NULL : subargs[pos];

			while (isspace(**data)) (*data)++;
			continue;
		}

		if (nextarg == NULL)
			break;

		if (*arglist[pos] == '@' && !isdigit(**data))
			break; /* expected a numeric argument */

		/* save the sub-argument to `nextarg' */
		arg = cmd_get_quoted_param(data);
                *nextarg = arg; nextarg = NULL;

		while (isspace(**data)) (*data)++;
	}

	/* ok, this is a bit stupid. this will pack the arguments in `data'
	   like "-arg1 subarg -arg2 sub2\0" -> "-arg1 -arg2\0subarg\0sub2\0"
	   this is because it's easier to free only _one_ string instead of
	   two (`args') when using PARAM_FLAG_MULTIARGS. */
	if (origdata == *data)
		*args = "";
	else {
		cmd_params_pack(subargs, **data == '\0' ? *data : (*data)-1,
				origdata, origdata+returnargs->len);

		g_string_truncate(returnargs, returnargs->len-1);
		strcpy(origdata, returnargs->str);
		*args = origdata;
	}

	g_string_free(returnargs, TRUE);
	g_strfreev(arglist);
	g_free(subargs);

	return eat;
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

char *cmd_get_params(const char *data, int count, ...)
{
	char **str, *arg, *ret, *datad;
	va_list args;
	int cnt, eat;

	g_return_val_if_fail(data != NULL, NULL);

	va_start(args, count);
	ret = datad = cmd_get_callfuncs(data, &count, &args);

	cnt = PARAM_WITHOUT_FLAGS(count);
	while (cnt-- > 0) {
		if (count & PARAM_FLAG_OPTARGS) {
			arg = get_opt_args(&datad);
			count &= ~PARAM_FLAG_OPTARGS;
		} else if (count & PARAM_FLAG_MULTIARGS) {
			eat = get_multi_args(&datad, args)+1;
			count &= ~PARAM_FLAG_MULTIARGS;

			cnt -= eat-1;
			while (eat-- > 0)
				str = (char **) va_arg(args, char **);
			continue;
		} else if (cnt == 0 && count & PARAM_FLAG_GETREST) {
			/* get rest */
			arg = datad;
		} else {
			arg = cmd_get_quoted_param(&datad);
		}

		str = (char **) va_arg(args, char **);
		if (str != NULL) *str = arg;
	}
	va_end(args);

	return ret;
}

void cmd_get_add_func(CMD_GET_FUNC func)
{
        cmdget_funcs = g_slist_prepend(cmdget_funcs, (void *) func);
}

void cmd_get_remove_func(CMD_GET_FUNC func)
{
        cmdget_funcs = g_slist_prepend(cmdget_funcs, (void *) func);
}

static void parse_outgoing(const char *line, SERVER_REC *server, void *item)
{
	const char *cmdchars, *alias;
	char *cmd, *str, *args, *oldcmd;
	int use_alias = TRUE;

	g_return_if_fail(line != NULL);

	if (*line == '\0') {
		/* empty line, forget it. */
                signal_stop();
		return;
	}

	cmdchars = settings_get_str("cmdchars");
	if (strchr(cmdchars, *line) == NULL)
		return; /* handle only /commands here */
	line++;

	/* //command ignores aliases */
	if (strchr(cmdchars, *line) != NULL) {
		line++;
		use_alias = FALSE;
	}

	cmd = str = g_strconcat("command ", line, NULL);
	args = strchr(cmd+8, ' ');
	if (args != NULL) *args++ = '\0'; else args = "";

	/* check if there's an alias for command */
	alias = use_alias ? alias_find(cmd+8) : NULL;
	if (alias != NULL)
		eval_special_string(alias, args, server, item);
	else {
		if (server != NULL)
			server_redirect_default((SERVER_REC *) server, cmd);

		g_strdown(cmd);
		oldcmd = current_command;
		current_command = cmd+8;
		if (!signal_emit(cmd, 3, args, server, item))
			signal_emit_id(signal_default_command, 3, line, server, item);
                current_command = oldcmd;
	}

	g_free(str);
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

void commands_init(void)
{
	cmdget_funcs = NULL;
	current_command = NULL;

	signal_default_command = module_get_uniq_id_str("signals", "default command");

	settings_add_str("misc", "cmdchars", "/");
	signal_add("send command", (SIGNAL_FUNC) parse_outgoing);

	command_bind("eval", NULL, (SIGNAL_FUNC) cmd_eval);
	command_bind("cd", NULL, (SIGNAL_FUNC) cmd_cd);
}

void commands_deinit(void)
{
	g_free_not_null(current_command);
	g_slist_free(cmdget_funcs);

	signal_remove("send command", (SIGNAL_FUNC) parse_outgoing);

	command_unbind("eval", (SIGNAL_FUNC) cmd_eval);
	command_unbind("cd", (SIGNAL_FUNC) cmd_cd);
}
