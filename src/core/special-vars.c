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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "special-vars.h"
#include "settings.h"
#include "misc.h"
#include "irssi-version.h"

#include <sys/utsname.h>

#define ALIGN_RIGHT 0x01
#define ALIGN_CUT   0x02

static EXPANDO_FUNC char_expandos[256];
static GHashTable *expandos;
static time_t client_start_time;
static SPECIAL_HISTORY_FUNC history_func;

static char *get_argument(char **cmd, char **arglist)
{
	GString *str;
	char *ret;
	int max, arg, argcount;

	arg = 0;
	max = -1;

	argcount = strarray_length(arglist);

	if (**cmd == '*') {
		/* get all arguments */
	} else if (**cmd == '~') {
		/* get last argument */
		arg = max = argcount-1;
	} else {
		if (isdigit(**cmd)) {
			/* first argument */
			arg = max = (**cmd)-'0';
			(*cmd)++;
		}

		if (**cmd == '-') {
			/* get more than one argument */
			(*cmd)++;
			if (!isdigit(**cmd))
				max = -1; /* get all the rest */
			else {
				max = (**cmd)-'0';
				(*cmd)++;
			}
		}
		(*cmd)--;
	}

	str = g_string_new(NULL);
	while (arg < argcount && (arg <= max || max == -1)) {
		g_string_append(str, arglist[arg]);
		g_string_append_c(str, ' ');
		arg++;
	}
	if (str->len > 0) g_string_truncate(str, str->len-1);

	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

static char *get_internal_setting(const char *key, int type, int *free_ret)
{
	switch (type) {
	case SETTING_TYPE_BOOLEAN:
		return settings_get_bool(key) ? "yes" : "no";
	case SETTING_TYPE_INT:
		*free_ret = TRUE;
		return g_strdup_printf("%d", settings_get_int(key));
	case SETTING_TYPE_STRING:
		return (char *) settings_get_str(key);
	}

	return NULL;
}

static char *get_long_variable_value(const char *key, void *server, void *item, int *free_ret)
{
	EXPANDO_FUNC func;
	char *ret;
	int type;

	*free_ret = FALSE;

	/* expando? */
	func = g_hash_table_lookup(expandos, key);
	if (func != NULL)
		return func(server, item, free_ret);

	/* internal setting? */
	type = settings_get_type(key);
	if (type != -1)
		return get_internal_setting(key, type, free_ret);

	/* environment variable? */
	ret = g_getenv(key);
	if (ret != NULL) {
                *free_ret = TRUE;
		return ret;
	}

	return NULL;
}

static char *get_long_variable(char **cmd, void *server, void *item, int *free_ret)
{
	char *start, *var, *ret;

	/* get variable name */
	start = *cmd;
	while (isalnum((*cmd)[1])) (*cmd)++;

	var = g_strndup(start, (int) (*cmd-start)+1);
	ret = get_long_variable_value(var, server, item, free_ret);
	g_free(var);
	return ret;
}

/* return the value of the variable found from `cmd' */
static char *get_variable(char **cmd, void *server, void *item, char **arglist, int *free_ret, int *arg_used)
{
	if (isdigit(**cmd) || **cmd == '*' || **cmd == '-' || **cmd == '~') {
                /* argument */
		*free_ret = TRUE;
		if (arg_used != NULL) *arg_used = TRUE;
		return get_argument(cmd, arglist);
	}

	if (isalpha(**cmd) && isalnum((*cmd)[1])) {
		/* long variable name.. */
		return get_long_variable(cmd, server, item, free_ret);
	}

	/* single character variable. */
	*free_ret = FALSE;
	return char_expandos[(int) **cmd] == NULL ? NULL :
		char_expandos[(int) **cmd](server, item, free_ret);
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
		text = g_strndup(start, (int) (*cmd-start)+1);
		ret = history_func(text, item, free_ret);
		g_free(text);
	}

	if (**cmd == '\0') (*cmd)--;
	return ret;
}

static char *get_special_value(char **cmd, void *server, void *item, char **arglist, int *free_ret, int *arg_used)
{
	char command, *value, *p;
	int len;

	if (**cmd == '!') {
		/* find text from command history */
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

			*free_ret = TRUE;
			return get_argument(&temp_cmd, arglist);
		}
	}

	value = get_variable(cmd, server, item, arglist, free_ret, arg_used);

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

	*align = 0;
	*flags = ALIGN_CUT;
        *pad = ' ';

	/* '!' = don't cut, '-' = right padding */
	str = *data;
	while (*str != '\0' && *str != ']' && !isdigit(*str)) {
		if (*str == '!')
			*flags &= ~ALIGN_CUT;
		else if (*str == '-')
			*flags |= ALIGN_RIGHT;
		str++;
	}
	if (!isdigit(*str))
		return FALSE; /* expecting number */

	/* get the alignment size */
	while (isdigit(*str)) {
		*align = (*align) * 10 + (*str-'0');
		str++;
	}

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
static char *get_alignment(const char *text, int align, int flags, char pad)
{
	GString *str;
	char *ret;

	g_return_val_if_fail(text != NULL, NULL);

	str = g_string_new(text);

	/* cut */
	if ((flags & ALIGN_CUT) && align > 0 && str->len > align)
		g_string_truncate(str, align);

	/* add pad characters */
	while (str->len < align) {
		if (flags & ALIGN_RIGHT)
			g_string_prepend_c(str, pad);
		else
			g_string_append_c(str, pad);
	}

	ret = str->str;
        g_string_free(str, FALSE);
	return ret;
}

/* Parse and expand text after '$' character. return value has to be
   g_free()'d if `free_ret' is TRUE. */
char *parse_special(char **cmd, void *server, void *item, char **arglist, int *free_ret, int *arg_used)
{
	static char **nested_orig_cmd = NULL; /* FIXME: KLUDGE! */
	char command, *value;

	char align_pad;
	int align, align_flags;

	char *nest_value;
	int brackets, nest_free;

	*free_ret = FALSE;

	command = **cmd; (*cmd)++;
	switch (command) {
	case '[':
		/* alignment */
		if (!get_alignment_args(cmd, &align, &align_flags, &align_pad) ||
		    **cmd == '\0') {
                        (*cmd)--;
			return NULL;
		}
		break;
	default:
		command = 0;
		(*cmd)--;
	}

	nest_free = FALSE; nest_value = NULL;
	if (**cmd == '(') {
		/* subvariable */
		int toplevel = nested_orig_cmd == NULL;

		if (toplevel) nested_orig_cmd = cmd;
		(*cmd)++;
		if (**cmd != '$') {
			/* ... */
			nest_value = *cmd;
		} else {
			(*cmd)++;
			nest_value = parse_special(cmd, server, item, arglist, &nest_free, arg_used);
		}

		while ((*nested_orig_cmd)[1] != '\0') {
			(*nested_orig_cmd)++;
			if (**nested_orig_cmd == ')') break;
		}
		cmd = &nest_value;

                if (toplevel) nested_orig_cmd = NULL;
	}

	if (**cmd != '{')
		brackets = FALSE;
	else {
		/* special value is inside {...} (foo${test}bar -> fooXXXbar) */
		(*cmd)++;
		brackets = TRUE;
	}

	value = get_special_value(cmd, server, item, arglist, free_ret, arg_used);
	if (**cmd == '\0')
		g_error("parse_special() : buffer overflow!");

	if (brackets) {
		while (**cmd != '}' && (*cmd)[1] != '\0')
			(*cmd)++;
	}

	if (nest_free) g_free(nest_value);

	if (command == '[') {
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

/* parse the whole string. $ and \ chars are replaced */
char *parse_special_string(const char *cmd, void *server, void *item, const char *data, int *arg_used)
{
	char code, **arglist, *ret;
	GString *str;
	int need_free;

	g_return_val_if_fail(cmd != NULL, NULL);
	g_return_val_if_fail(data != NULL, NULL);

	/* create the argument list */
	arglist = g_strsplit(data, " ", -1);

	if (arg_used != NULL) *arg_used = FALSE;
	code = 0;
	str = g_string_new(NULL);
	while (*cmd != '\0') {
		if (code == '\\'){
			g_string_append_c(str, *cmd);
			code = 0;
		} else if (code == '$') {
			char *ret;

			ret = parse_special((char **) &cmd, server, item, arglist, &need_free, arg_used);
			if (ret != NULL) {
				g_string_append(str, ret);
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

	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

/* execute the commands in string - commands can be split with ';' */
void eval_special_string(const char *cmd, const char *data, void *server, void *item)
{
	const char *cmdchars;
	char *orig, *str, *start, *ret;
	int arg_used;

	cmdchars = settings_get_str("cmdchars");
	orig = start = str = g_strdup(cmd);
	do {
		if (*str == ';' && (start == str || (str[-1] != '\\' && str[-1] != '$')))
			*str++ = '\0';
		else if (*str != '\0') {
			str++;
			continue;
		}

		ret = parse_special_string(start, server, item, data, &arg_used);
		if (strchr(cmdchars, *ret) == NULL) {
                        /* no command char - let's put it there.. */
			char *old = ret;

			ret = g_strdup_printf("%c%s", *cmdchars, old);
			g_free(old);
		}
		if (!arg_used && *data != '\0') {
			/* append the string with all the arguments */
			char *old = ret;

			ret = g_strconcat(old, " ", data, NULL);
			g_free(old);
		}
		signal_emit("send command", 3, ret, server, item);
		g_free(ret);

		start = str;
	} while (*start != '\0');

	g_free(orig);
}

/* Create expando - overrides any existing ones. */
void expando_create(const char *key, EXPANDO_FUNC func)
{
	gpointer origkey, origvalue;

	g_return_if_fail(key != NULL || *key == '\0');
	g_return_if_fail(func != NULL);

	if (key[1] == '\0') {
		/* single character expando */
		char_expandos[(int) *key] = func;
		return;
	}

	if (g_hash_table_lookup_extended(expandos, key, &origkey, &origvalue)) {
                g_free(origkey);
		g_hash_table_remove(expandos, key);
	}
	g_hash_table_insert(expandos, g_strdup(key), func);
}

/* Destroy expando */
void expando_destroy(const char *key, EXPANDO_FUNC func)
{
	gpointer origkey, origvalue;

	g_return_if_fail(key != NULL || *key == '\0');
	g_return_if_fail(func != NULL);

	if (key[1] == '\0') {
		/* single character expando */
		if (char_expandos[(int) *key] == func)
                        char_expandos[(int) *key] = NULL;
		return;
	}

	if (g_hash_table_lookup_extended(expandos, key, &origkey, &origvalue)) {
                g_free(origkey);
		g_hash_table_remove(expandos, key);
	}
}

void special_history_func_set(SPECIAL_HISTORY_FUNC func)
{
	history_func = func;
}

/* time client was started, $time() format */
static char *expando_clientstarted(void *server, void *item, int *free_ret)
{
        *free_ret = TRUE;
	return g_strdup_printf("%ld", (long) client_start_time);
}

/* client version text string */
static char *expando_version(void *server, void *item, int *free_ret)
{
	return IRSSI_VERSION;
}

/* current value of CMDCHARS */
static char *expando_cmdchars(void *server, void *item, int *free_ret)
{
	return (char *) settings_get_str("cmdchars");
}

/* client release date (numeric version string) */
static char *expando_releasedate(void *server, void *item, int *free_ret)
{
	return IRSSI_VERSION_DATE;
}

/* current working directory */
static char *expando_workdir(void *server, void *item, int *free_ret)
{
	*free_ret = TRUE;
	return g_get_current_dir();
}

/* time of day (hh:mm) */
static char *expando_time(void *server, void *item, int *free_ret)
{
	time_t now = time(NULL);
	struct tm *tm;

	tm = localtime(&now);
	*free_ret = TRUE;
	return g_strdup_printf("%02d:%02d", tm->tm_hour, tm->tm_min);
}

/* a literal '$' */
static char *expando_dollar(void *server, void *item, int *free_ret)
{
	return "$";
}

/* system name */
static char *expando_sysname(void *server, void *item, int *free_ret)
{
	struct utsname un;

	if (uname(&un) != 0)
		return NULL;

	*free_ret = TRUE;
	return g_strdup(un.sysname);

}

/* system release */
static char *expando_sysrelease(void *server, void *item, int *free_ret)
{
	struct utsname un;

	if (uname(&un) != 0)
		return NULL;

	*free_ret = TRUE;
	return g_strdup(un.release);

}

void special_vars_init(void)
{
	client_start_time = time(NULL);

	memset(char_expandos, 0, sizeof(char_expandos));
	expandos = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);
	history_func = NULL;

	char_expandos['F'] = expando_clientstarted;
	char_expandos['J'] = expando_version;
	char_expandos['K'] = expando_cmdchars;
	char_expandos['V'] = expando_releasedate;
	char_expandos['W'] = expando_workdir;
	char_expandos['Z'] = expando_time;
	char_expandos['$'] = expando_dollar;

	expando_create("sysname", expando_sysname);
	expando_create("sysrelease", expando_sysrelease);
}

void special_vars_deinit(void)
{
	expando_destroy("sysname", expando_sysname);
	expando_destroy("sysrelease", expando_sysrelease);

        g_hash_table_destroy(expandos);
}
