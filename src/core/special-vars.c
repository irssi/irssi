/*
 special-vars.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include <irssi/src/core/expandos.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/refstrings.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/utf8.h>

#define isvarchar(c) \
        (i_isalnum(c) || (c) == '_')

#define isarg(c) \
	(i_isdigit(c) || (c) == '*' || (c) == '~' || (c) == '-')

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION /* fuzzer should not exhaust memory here */
#define ALIGN_MAX 512
#else
#define ALIGN_MAX 222488
#endif

static SPECIAL_HISTORY_FUNC history_func = NULL;
static GSList *special_collector;
static GSList *special_cache;

static char *get_argument(char **cmd, char **arglist)
{
	GString *str;
	char *ret;
	int max, arg, argcount;

	arg = 0;
	max = -1;

	argcount = arglist == NULL ? 0 : g_strv_length(arglist);

	if (**cmd == '*') {
		/* get all arguments */
	} else if (**cmd == '~') {
		/* get last argument */
		arg = max = argcount-1;
	} else {
		if (i_isdigit(**cmd)) {
			/* first argument */
			arg = max = (**cmd)-'0';
			(*cmd)++;
		}

		if (**cmd == '-') {
			/* get more than one argument */
			(*cmd)++;
			if (!i_isdigit(**cmd))
				max = -1; /* get all the rest */
			else {
				max = (**cmd)-'0';
				(*cmd)++;
			}
		}
		(*cmd)--;
	}

	str = g_string_new(NULL);
	while (arg >= 0 && arg < argcount && (arg <= max || max == -1)) {
		g_string_append(str, arglist[arg]);
		g_string_append_c(str, ' ');
		arg++;
	}
	if (str->len > 0) g_string_truncate(str, str->len-1);

	ret = g_string_free_and_steal(str);
	return ret;
}

static char *get_long_variable_value(const char *key, SERVER_REC *server,
				     void *item, int *free_ret)
{
	EXPANDO_FUNC func;
	const char *ret;
	SETTINGS_REC *rec;

	*free_ret = FALSE;

	/* expando? */
        func = expando_find_long(key);
	if (func != NULL) {
		current_expando = key;
		return func(server, item, free_ret);
	}

	/* internal setting? */
	rec = settings_get_record(key);
	if (rec != NULL) {
		*free_ret = TRUE;
		return settings_get_print(rec);
	}

	/* environment variable? */
	ret = g_getenv(key);
	if (ret != NULL)
		return (char *) ret;

	return NULL;
}

static gboolean cache_find(GSList **cache, const char *var, char **ret)
{
	GSList *tmp;
	GSList *prev = NULL;

	if (cache == NULL)
		return FALSE;

	for (tmp = *cache; tmp;) {
		if (g_strcmp0(var, tmp->data) == 0) {
			*ret = tmp->next->data;
			if (prev != NULL)
				prev->next->next = tmp->next->next;
			else
				*cache = tmp->next->next;

			g_slist_free_1(tmp->next);
			g_slist_free_1(tmp);
			return TRUE;
		}
		prev = tmp;
		tmp = tmp->next->next;
	}
	return FALSE;
}

static gboolean cache_find_char(GSList **cache, char var, char **ret)
{
	char varn[] = { var, '\0' };
	return cache_find(cache, varn, ret);
}

static char *get_long_variable(char **cmd, SERVER_REC *server, void *item, int *free_ret,
                               int getname, GSList **collector, GSList **cache)
{
	char *start, *var, *ret;

	/* get variable name */
	start = *cmd;
	while (isvarchar((*cmd)[1])) (*cmd)++;

	var = g_strndup(start, (int) (*cmd-start)+1);
	if (getname) {
		*free_ret = TRUE;
                return var;
	}
	if (cache_find(cache, var, &ret)) {
		g_free(var);
		return ret;
	}
	ret = get_long_variable_value(var, server, item, free_ret);
	if (collector != NULL) {
		*collector = g_slist_prepend(*collector, g_strdup(ret));
		*collector = g_slist_prepend(*collector, i_refstr_intern(var));
	}
	g_free(var);
	return ret;
}

/* return the value of the variable found from `cmd'.
   if 'getname' is TRUE, return the name of the variable instead it's value */
static char *get_variable(char **cmd, SERVER_REC *server, void *item, char **arglist, int *free_ret,
                          int *arg_used, int getname, GSList **collector, GSList **cache)
{
	EXPANDO_FUNC func;

	if (isarg(**cmd)) {
		/* argument */
		*free_ret = TRUE;
		if (arg_used != NULL) *arg_used = TRUE;
		return getname ? g_strdup_printf("%c", **cmd) :
			get_argument(cmd, arglist);
	}

	if (i_isalpha(**cmd) && isvarchar((*cmd)[1])) {
		/* long variable name.. */
		return get_long_variable(cmd, server, item, free_ret, getname, collector, cache);
	}

	/* single character variable. */
	if (getname) {
		*free_ret = TRUE;
                return g_strdup_printf("%c", **cmd);
	}
	*free_ret = FALSE;
	{
		char *ret;
		if (cache_find_char(cache, **cmd, &ret)) {
			return ret;
		}
	}
	func = expando_find_char(**cmd);
	if (func == NULL)
		return NULL;
	else {
		char str[2];
		char *ret;

		str[0] = **cmd; str[1] = '\0';
		current_expando = str;
		ret = func(server, item, free_ret);
		if (**cmd != 'Z' && collector != NULL) {
			*collector = g_slist_prepend(*collector, g_strdup(ret));
			*collector = g_slist_prepend(*collector, i_refstr_intern(str));
		}
		return ret;
	}
}

static char *get_history(char **cmd, void *item, int *free_ret)
{
	char *start, *text, *ret;

	/* get variable name */
	start = ++(*cmd);
	while (**cmd != '\0' && **cmd != '!') (*cmd)++;

	if (history_func == NULL)
		ret = NULL;
	else {
		text = g_strndup(start, (int) (*cmd-start));
		ret = history_func(text, item, free_ret);
		g_free(text);
	}

	if (**cmd == '\0') (*cmd)--;
	return ret;
}

static char *get_special_value(char **cmd, SERVER_REC *server, void *item, char **arglist,
                               int *free_ret, int *arg_used, int flags, GSList **collector,
                               GSList **cache)
{
	char command, *value, *p;
	int len;

	if ((flags & PARSE_FLAG_ONLY_ARGS) && !isarg(**cmd)) {
		*free_ret = TRUE;
		return g_strdup_printf("$%c", **cmd);
	}

	if (**cmd == '!') {
		/* find text from command history */
		if (flags & PARSE_FLAG_GETNAME)
			return "!";

		return get_history(cmd, item, free_ret);
	}

	command = 0;
	if (**cmd == '#' || **cmd == '@') {
                command = **cmd;
		if ((*cmd)[1] != '\0')
			(*cmd)++;
		else {
			/* default to $* */
			char *temp_cmd = "*";

			if (flags & PARSE_FLAG_GETNAME)
                                return "*";

			*free_ret = TRUE;
			return get_argument(&temp_cmd, arglist);
		}
	}

	value = get_variable(cmd, server, item, arglist, free_ret, arg_used,
	                     flags & PARSE_FLAG_GETNAME, collector, cache);

	if (flags & PARSE_FLAG_GETNAME)
		return value;

	if (command == '#') {
		/* number of words */
		if (value == NULL || *value == '\0') {
			if (value != NULL && *free_ret) {
				g_free(value);
				*free_ret = FALSE;
			}
			return "0";
		}

		len = 1;
		for (p = value; *p != '\0'; p++) {
			if (*p == ' ' && (p[1] != ' ' && p[1] != '\0'))
				len++;
		}
                if (*free_ret) g_free(value);

		*free_ret = TRUE;
		return g_strdup_printf("%d", len);
	}

	if (command == '@') {
		/* number of characters */
		if (value == NULL) return "0";

		len = strlen(value);
                if (*free_ret) g_free(value);

		*free_ret = TRUE;
		return g_strdup_printf("%d", len);
	}

	return value;
}

/* get alignment arguments (inside the []) */
static int get_alignment_args(char **data, int *align, int *flags, char *pad)
{
	char *str;
	char *endptr;
	guint align_;

	*align = 0;
	*flags = ALIGN_CUT|ALIGN_PAD;
        *pad = ' ';

	/* '!' = don't cut, '-' = right padding */
	str = *data;
	while (*str != '\0' && *str != ']' && !i_isdigit(*str)) {
		if (*str == '!')
			*flags &= ~ALIGN_CUT;
		else if (*str == '-')
			*flags |= ALIGN_RIGHT;
		else if (*str == '.')
                         *flags &= ~ALIGN_PAD;
		str++;
	}
	if (!i_isdigit(*str))
		return FALSE; /* expecting number */

	/* get the alignment size */
	if (!parse_uint(str, &endptr, 10, &align_)) {
		return FALSE;
	}
	/* alignment larger than supported */
	if (align_ > ALIGN_MAX) {
		return FALSE;
	}
	str = endptr;
	*align = align_;

	/* get the pad character */
	while (*str != '\0' && *str != ']') {
		*pad = *str;
		str++;
	}

	if (*str++ != ']') return FALSE;

	*data = str;
	return TRUE;
}

/* return the aligned text */
char *get_alignment(const char *text, int align, int flags, char pad)
{
	GString *str;
	char *ret;
	int policy;
	unsigned int cut_bytes;

	g_return_val_if_fail(text != NULL, NULL);

	policy = string_policy(text);

	str = g_string_new(text);

	/* cut */
	if ((flags & ALIGN_CUT) && align > 0 && string_width(text, policy) > align) {
		string_chars_for_width(text, policy, align, &cut_bytes);
		g_string_truncate(str, cut_bytes);
	}

	/* add pad characters */
	if (flags & ALIGN_PAD) {
		int pad_len = align - string_width(str->str, policy);
		if (pad_len > 0) {
			char *pad_full = g_strnfill(pad_len, pad);
			if (flags & ALIGN_RIGHT)
				g_string_prepend(str, pad_full);
			else
				g_string_append(str, pad_full);
			g_free(pad_full);
		}
	}

	ret = g_string_free_and_steal(str);
	return ret;
}

/* Parse and expand text after '$' character. return value has to be
   g_free()'d if `free_ret' is TRUE. */
char *parse_special(char **cmd, SERVER_REC *server, void *item,
		    char **arglist, int *free_ret, int *arg_used, int flags)
{
	static char **nested_orig_cmd = NULL; /* FIXME: KLUDGE! */
	char command, *value;

	char align_pad = '\0';
	int align = 0, align_flags = 0;

	char *nest_value;
	int brackets, nest_free;

	*free_ret = FALSE;
	if (**cmd == '\0')
		return NULL;

	command = **cmd; (*cmd)++;
	switch (command) {
	case '[':
		/* alignment */
		if (!get_alignment_args(cmd, &align, &align_flags,
					&align_pad) || **cmd == '\0') {
			(*cmd)--;
			return NULL;
		}
		break;
	default:
		command = 0;
		(*cmd)--;
	}

	nest_free = FALSE; nest_value = NULL;
#if 0 /* this code is disabled due to security issues until it is fixed */
	if (**cmd == '(' && (*cmd)[1] != '\0') {
		/* subvariable */
		int toplevel = nested_orig_cmd == NULL;

		if (toplevel) nested_orig_cmd = cmd;
		(*cmd)++;
		if (**cmd != '$') {
			/* ... */
			nest_value = *cmd;
		} else {
			(*cmd)++;
			nest_value = parse_special(cmd, server, item, arglist,
						   &nest_free, arg_used,
						   flags);
		}

		if (nest_value == NULL || *nest_value == '\0')
			return NULL;

		while ((*nested_orig_cmd)[1] != '\0') {
			(*nested_orig_cmd)++;
			if (**nested_orig_cmd == ')')
				break;
		}
		cmd = &nest_value;

                if (toplevel) nested_orig_cmd = NULL;
	}
#else
	if (nested_orig_cmd) nested_orig_cmd = NULL;
#endif

	if (**cmd != '{')
		brackets = FALSE;
	else {
		/* special value is inside {...} (foo${test}bar -> fooXXXbar) */
		if ((*cmd)[1] == '\0')
			return NULL;
		(*cmd)++;
		brackets = TRUE;
	}

	value = get_special_value(cmd, server, item, arglist, free_ret, arg_used, flags,
	                          special_collector != NULL ? special_collector->data : NULL,
	                          &special_cache);
	if (**cmd == '\0')
		g_error("parse_special() : buffer overflow!");

	if (value != NULL && *value != '\0' && (flags & PARSE_FLAG_ISSET_ANY))
		*arg_used = TRUE;

	if (brackets) {
		while (**cmd != '}' && (*cmd)[1] != '\0')
			(*cmd)++;
	}

	if (nest_free) g_free(nest_value);

	if (command == '[' && (flags & PARSE_FLAG_GETNAME) == 0) {
		/* alignment */
		char *p;

		if (value == NULL) return "";

		p = get_alignment(value, align, align_flags, align_pad);
		if (*free_ret) g_free(value);

		*free_ret = TRUE;
		return p;
	}

	return value;
}

static void gstring_append_escaped(GString *str, const char *text, int flags)
{
	char esc[4], *escpos;

	escpos = esc;
	if (flags & PARSE_FLAG_ESCAPE_VARS)
		*escpos++ = '%';
	if (flags & PARSE_FLAG_ESCAPE_THEME) {
		*escpos++ = '{';
		*escpos++ = '}';
	}

	if (escpos == esc) {
		g_string_append(str, text);
		return;
	}

	*escpos = '\0';
	while (*text != '\0') {
		for (escpos = esc; *escpos != '\0'; escpos++) {
			if (*text == *escpos) {
	                        g_string_append_c(str, '%');
	                        break;
	                }
		}
		g_string_append_c(str, *text);
		text++;
	}
}

/* parse the whole string. $ and \ chars are replaced */
char *parse_special_string(const char *cmd, SERVER_REC *server, void *item,
			   const char *data, int *arg_used, int flags)
{
	char code, **arglist, *ret;
	GString *str;
	int need_free, chr;

	g_return_val_if_fail(cmd != NULL, NULL);
	g_return_val_if_fail(data != NULL, NULL);

	/* create the argument list */
	arglist = g_strsplit(data, " ", -1);

	if (arg_used != NULL) *arg_used = FALSE;
	code = 0;
	str = g_string_new(NULL);
	while (*cmd != '\0') {
		if (code == '\\') {
			if (*cmd == ';')
				g_string_append_c(str, ';');
			else {
				chr = expand_escape(&cmd);
				g_string_append_c(str, chr != -1 ? chr : *cmd);
			}
			code = 0;
		} else if (code == '$') {
			char *ret;

			ret = parse_special((char **) &cmd, server, item,
					    arglist, &need_free, arg_used,
					    flags);
			if (ret != NULL) {
                                gstring_append_escaped(str, ret, flags);
				if (need_free) g_free(ret);
			}
			code = 0;
		} else {
			if (*cmd == '\\' || *cmd == '$')
				code = *cmd;
			else
				g_string_append_c(str, *cmd);
		}

                cmd++;
	}
	g_strfreev(arglist);

	ret = g_string_free_and_steal(str);
	return ret;
}

#define is_split_char(str, start) \
	((str)[0] == ';' && ((start) == (str) || \
		((str)[-1] != '\\' && (str)[-1] != '$')))

/* execute the commands in string - commands can be split with ';' */
void eval_special_string(const char *cmd, const char *data,
			 SERVER_REC *server, void *item)
{
	const char *cmdchars;
	char *orig, *str, *start, *ret;
	int arg_used, arg_used_ever;
	GSList *commands;

	commands = NULL;
	arg_used_ever = FALSE;
	cmdchars = settings_get_str("cmdchars");

	/* get a list of all the commands to run */
	orig = start = str = g_strdup(cmd);
	do {
		if (is_split_char(str, start)) {
			*str++ = '\0';
                        while (*str == ' ') str++;
		} else if (*str != '\0') {
			str++;
			continue;
		}

		ret = parse_special_string(start, server, item,
					   data, &arg_used, 0);
		if (*ret != '\0') {
			if (arg_used) arg_used_ever = TRUE;

			if (strchr(cmdchars, *ret) == NULL) {
				/* no command char - let's put it there.. */
				char *old = ret;

				ret = g_strdup_printf("%c%s", *cmdchars, old);
				g_free(old);
			}
			commands = g_slist_append(commands, ret);
		}
		start = str;
	} while (*start != '\0');

	/* run the command, if no arguments were ever used, append all of them
	   after each command */
	while (commands != NULL) {
		ret = commands->data;

		if (!arg_used_ever && *data != '\0') {
			char *old = ret;

			ret = g_strconcat(old, " ", data, NULL);
			g_free(old);
		}

                if (server != NULL)
			server_ref(server);
		signal_emit("send command", 3, ret, server, item);

		if (server != NULL && !server_unref(server)) {
                        /* the server was destroyed */
			server = NULL;
                        item = NULL;
		}

		/* FIXME: window item would need reference counting as well,
		   eg. "/EVAL win close;say hello" wouldn't work now.. */

		commands = g_slist_remove(commands, commands->data);
		g_free(ret);
	}
	g_free(orig);
}

void special_history_func_set(SPECIAL_HISTORY_FUNC func)
{
	history_func = func;
}

void special_push_collector(GSList **list)
{
	special_collector = g_slist_prepend(special_collector, list);
}

void special_pop_collector(void)
{
	special_collector = g_slist_delete_link(special_collector, special_collector);
}

void special_fill_cache(GSList *list)
{
	g_slist_free(special_cache);
	special_cache = g_slist_copy(list);
}

static void update_signals_hash(GHashTable **hash, int *signals)
{
	void *signal_id;
        int arg_type;

	if (*hash == NULL) {
		*hash = g_hash_table_new((GHashFunc) g_direct_hash,
					 (GCompareFunc) g_direct_equal);
	}

	while (*signals != -1) {
                signal_id = GINT_TO_POINTER(*signals);
		arg_type = GPOINTER_TO_INT(g_hash_table_lookup(*hash, signal_id));
		if (arg_type != 0 && arg_type != signals[1]) {
			/* same signal is used for different purposes ..
			   not sure if this should ever happen, but change
			   the argument type to none so it will at least
			   work. */
			arg_type = EXPANDO_ARG_NONE;
		}

		if (arg_type == 0) arg_type = signals[1];
		g_hash_table_insert(*hash, signal_id,
				    GINT_TO_POINTER(arg_type));
		signals += 2;
	}
}

static void get_signal_hash(void *signal_id, void *arg_type, int **pos)
{
	(*pos)[0] = GPOINTER_TO_INT(signal_id);
        (*pos)[1] = GPOINTER_TO_INT(arg_type);
        (*pos) += 2;
}

static int *get_signals_list(GHashTable *hash)
{
	int *signals, *pos;

	if (hash == NULL) {
		/* no expandos in text - never needs updating */
		return NULL;
	}

        pos = signals = g_new(int, g_hash_table_size(hash)*2 + 1);
	g_hash_table_foreach(hash, (GHFunc) get_signal_hash, &pos);
        *pos = -1;

	g_hash_table_destroy(hash);
        return signals;

}

#define TASK_BIND		1
#define TASK_UNBIND		2
#define TASK_GET_SIGNALS	3

static int *special_vars_signals_task(const char *text, int funccount,
				      SIGNAL_FUNC *funcs, int task)
{
        GHashTable *signals;
	char *expando;
	int need_free, *expando_signals;

        signals = NULL;
	while (*text != '\0') {
		if (*text == '\\' && text[1] != '\0') {
                        /* escape */
			text += 2;
		} else if (*text == '$' && text[1] != '\0') {
                        /* expando */
			text++;
			expando = parse_special((char **) &text, NULL, NULL,
						NULL, &need_free, NULL,
						PARSE_FLAG_GETNAME);
			if (expando == NULL)
				continue;

			switch (task) {
			case TASK_BIND:
				expando_bind(expando, funccount, funcs);
				break;
			case TASK_UNBIND:
				expando_unbind(expando, funccount, funcs);
				break;
			case TASK_GET_SIGNALS:
				expando_signals = expando_get_signals(expando);
				if (expando_signals != NULL) {
					update_signals_hash(&signals,
							    expando_signals);
                                        g_free(expando_signals);
				}
				break;
			}
			if (need_free) g_free(expando);
		} else {
                        /* just a char */
			text++;
		}
	}

	if (task == TASK_GET_SIGNALS)
                return get_signals_list(signals);

        return NULL;
}

void special_vars_add_signals(const char *text,
			      int funccount, SIGNAL_FUNC *funcs)
{
        special_vars_signals_task(text, funccount, funcs, TASK_BIND);
}

void special_vars_remove_signals(const char *text,
				 int funccount, SIGNAL_FUNC *funcs)
{
        special_vars_signals_task(text, funccount, funcs, TASK_UNBIND);
}

int *special_vars_get_signals(const char *text)
{
	return special_vars_signals_task(text, 0, NULL, TASK_GET_SIGNALS);
}

void special_vars_init(void)
{
	special_cache = NULL;
	special_collector = NULL;
}

void special_vars_deinit(void)
{
	g_slist_free(special_cache);
	g_slist_free(special_collector);
}
