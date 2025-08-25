/*
 completion.c : irssi

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
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/fe-common/core/completion.h>
#include <irssi/src/fe-common/core/printtext.h>

static GList *complist; /* list of commands we're currently completing */
static char *last_line;
static int last_want_space, last_line_pos;

#define isseparator_notspace(c) \
        ((c) == ',')

#define isseparator_space(c) \
        ((c) == ' ')

#define isseparator(c) \
	(isseparator_space(c) || isseparator_notspace(c))

void chat_completion_init(void);
void chat_completion_deinit(void);

static const char *completion_find(const char *key, int automatic)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("completions", FALSE);
	if (node == NULL || node->type != NODE_TYPE_BLOCK)
		return NULL;

	node = iconfig_node_section(node, key, -1);
	if (node == NULL)
		return NULL;

	if (automatic && !config_node_get_bool(node, "auto", FALSE))
		return NULL;

	return config_node_get_str(node, "value", NULL);
}

/* Return whole word at specified position in string */
static char *get_word_at(const char *str, int pos, char **startpos)
{
	const char *start, *end;

	g_return_val_if_fail(str != NULL, NULL);
	g_return_val_if_fail(pos >= 0, NULL);

	/* get previous word if char at `pos' is space */
	start = str+pos;
	while (start > str && isseparator(start[-1])) start--;

	end = start;
	while (start > str && !isseparator(start[-1])) start--;
	while (*end != '\0' && !isseparator(*end)) end++;
	while (*end != '\0' && isseparator_notspace(*end)) end++;

	*startpos = (char *) start;
	return g_strndup(start, (int) (end-start));
}

/* automatic word completion - called when space/enter is pressed */
char *auto_word_complete(const char *line, int *pos)
{
	GString *result;
	const char *replace;
	char *word, *wordstart, *ret;
	int startpos;

	g_return_val_if_fail(line != NULL, NULL);
	g_return_val_if_fail(pos != NULL, NULL);

	word = get_word_at(line, *pos, &wordstart);
	startpos = (int) (wordstart-line);

	result = g_string_new(line);
	g_string_erase(result, startpos, strlen(word));

	/* check for words in autocompletion list */
	replace = completion_find(word, TRUE);
	if (replace == NULL || (!g_strcmp0(replace, word))) {
		ret = NULL;
		g_string_free(result, TRUE);
	} else {
		*pos = startpos+strlen(replace);

		g_string_insert(result, startpos, replace);
		ret = g_string_free_and_steal(result);
	}

	g_free(word);
	return ret;
}

static void free_completions(void)
{
	complist = g_list_first(complist);

	g_list_foreach(complist, (GFunc) g_free, NULL);
	g_list_free(complist);
        complist = NULL;

	g_free_and_null(last_line);
}

/* manual word completion - called when TAB is pressed */
char *word_complete(WINDOW_REC *window, const char *line, int *pos, int erase, int backward)
{
	static int startpos = 0, wordlen = 0;
        int old_startpos, old_wordlen;

	GString *result;
	const char *cmdchars;
	char *word, *wordstart, *linestart, *ret, *data;
	int continue_complete, want_space, expand_escapes;

	g_return_val_if_fail(line != NULL, NULL);
	g_return_val_if_fail(pos != NULL, NULL);

	continue_complete = complist != NULL && *pos == last_line_pos &&
		g_strcmp0(line, last_line) == 0;

	if (erase && !continue_complete)
		return NULL;

	old_startpos = startpos;
	old_wordlen = wordlen;

	if (!erase && continue_complete) {
		word = NULL;
                linestart = NULL;
	} else {
		char* old_wordstart;

		/* get the word we want to complete */
		word = get_word_at(line, *pos, &wordstart);
		old_wordstart = wordstart;

		startpos = (int) (wordstart-line);
		wordlen = strlen(word);

		/* remove trailing spaces from linestart */
		while (wordstart > line && isseparator_space(wordstart[-1]))
			wordstart--;

		/* unless everything was spaces */
		if (old_wordstart > line && wordstart == line)
			wordstart = old_wordstart - 1;

		linestart = g_strndup(line, (int) (wordstart-line));

		/* completions usually add space after the word, that makes
		   things a bit harder. When continuing a completion
		   "/msg nick1 "<tab> we have to cycle to nick2, etc.
		   BUT if we start completion with "/msg "<tab>, we don't
		   want to complete the /msg word, but instead complete empty
		   word with /msg being in linestart. */
		if (!erase && *pos > 0 && isseparator_space(line[*pos-1]) &&
		    (*linestart == '\0' || !isseparator_space(wordstart[-1]))) {
			char *old;

			old = linestart;
			/* we want to move word into linestart */
			if (*linestart == '\0') {
				linestart = g_strdup(word);
			} else {
				GString *str = g_string_new(linestart);
				if (old_wordstart[-1] != str->str[str->len - 1]) {
					/* do not accidentally duplicate the word separator */
					g_string_append_c(str, old_wordstart[-1]);
				}
				g_string_append(str, word);
				linestart = g_string_free(str, FALSE);
			}
			g_free(old);

			g_free(word);
			word = g_strdup("");

			startpos = *linestart == '\0' ? 0 :
				strlen(linestart)+1;
			wordlen = 0;
		}

	}

	if (erase) {
		signal_emit("complete erase", 3, window, word, linestart);

                /* jump to next completion */
                startpos = old_startpos;
		wordlen = old_wordlen;
	}

	if (continue_complete) {
		/* complete from old list */
		if (backward)
			complist = complist->prev != NULL ? complist->prev :
				g_list_last(complist);
		else
			complist = complist->next != NULL ? complist->next :
				g_list_first(complist);
		want_space = last_want_space;
	} else {
		int keep_word = settings_get_bool("completion_keep_word");
		/* get new completion list */
		free_completions();

		want_space = TRUE;
		signal_emit("complete word", 5, &complist, window, word, linestart, &want_space);
		last_want_space = want_space;

		if (complist != NULL) {
			/* Remove all nulls (from the signal) before doing further processing */
			complist = g_list_remove_all(g_list_first(complist), NULL);

			if (keep_word) {
				complist = g_list_append(complist, g_strdup(word));
			}

			if (backward) {
				complist = g_list_last(complist);
				if (keep_word) {
					complist = complist->prev;
				}
			}
		}
	}

	g_free(linestart);
	g_free(word);

	if (complist == NULL)
		return NULL;

        /* get the cmd char */
	cmdchars = settings_get_str("cmdchars");

	/* get the expand_escapes setting */
	expand_escapes = settings_get_bool("expand_escapes");

	/* escape if the word doesn't begin with '/' and expand_escapes are turned on */
	data = strchr(cmdchars, *line) == NULL && expand_escapes ?
		escape_string_backslashes(complist->data) : g_strdup(complist->data);

	/* word completed */
	*pos = startpos + strlen(data);

	/* replace the word in line - we need to return
	   a full new line */
	result = g_string_new(line);
	g_string_erase(result, startpos, wordlen);
	g_string_insert(result, startpos, data);

	if (want_space) {
		if (!isseparator(result->str[*pos]))
			g_string_insert_c(result, *pos, ' ');
		(*pos)++;
	}

	wordlen = strlen(data);
	last_line_pos = *pos;
	g_free_not_null(last_line);
	last_line = g_strdup(result->str);

	ret = g_string_free_and_steal(result);

	/* free the data */
	g_free(data);

	return ret;
}

#define IS_CURRENT_DIR(dir) \
        ((dir)[0] == '.' && ((dir)[1] == '\0' || (dir)[1] == G_DIR_SEPARATOR))

#define USE_DEFAULT_PATH(path, default_path) \
	((!g_path_is_absolute(path) || IS_CURRENT_DIR(path)) && \
	 default_path != NULL)

static GList *list_add_file(GList *list, const char *name, const char *default_path)
{
	struct stat statbuf;
	char *fname;

	g_return_val_if_fail(name != NULL, NULL);

	fname = convert_home(name);
	if (USE_DEFAULT_PATH(fname, default_path)) {
                g_free(fname);
		fname = g_strconcat(default_path, G_DIR_SEPARATOR_S,
				    name, NULL);
	}
	if (stat(fname, &statbuf) == 0) {
		list = g_list_append(list, !S_ISDIR(statbuf.st_mode) ? g_strdup(name) :
				     g_strconcat(name, G_DIR_SEPARATOR_S, NULL));
	}

        g_free(fname);
	return list;
}

GList *filename_complete(const char *path, const char *default_path)
{
        GList *list;
	DIR *dirp;
	struct dirent *dp;
	char *basename;
	char *realpath, *dir, *name;
	size_t len;

	g_return_val_if_fail(path != NULL, NULL);

	if (path[0] == '\0') {
	    return NULL;
	}

	list = NULL;

	/* get directory part of the path - expand ~/ */
	realpath = convert_home(path);
	if (USE_DEFAULT_PATH(realpath, default_path)) {
                g_free(realpath);
		realpath = g_strconcat(default_path, G_DIR_SEPARATOR_S,
				       path, NULL);
	}

	/* open directory for reading */
	dir = g_path_get_dirname(realpath);
	dirp = opendir(dir);
	g_free(dir);
        g_free(realpath);

	if (dirp == NULL)
		return NULL;

	dir = g_path_get_dirname(path);
	if (*dir == G_DIR_SEPARATOR && dir[1] == '\0') {
                /* completing file in root directory */
		*dir = '\0';
	} else if (IS_CURRENT_DIR(dir) && !IS_CURRENT_DIR(path)) {
		/* completing file in default_path
		   (path not set, and leave it that way) */
		g_free_and_null(dir);
	}

	len = strlen(path);
	/* g_path_get_basename() returns the component before the last slash if
	 * the path ends with a directory separator, that's not what we want */
	if (len > 0 && path[len - 1] == G_DIR_SEPARATOR) {
	    basename = g_strdup("");
	} else {
	    basename = g_path_get_basename(path);
	}
	len = strlen(basename);

	/* add all files in directory to completion list */
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.') {
			if (dp->d_name[1] == '\0' ||
			    (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))
				continue; /* skip . and .. */

			/* Skip the dotfiles unless the user explicitly asked us
			 * to do so. Basename might be './', beware of that */
			if (basename[0] != '.' || basename[1] == '\0')
				continue;
		}

		if (len == 0 || strncmp(dp->d_name, basename, len) == 0) {
			name = dir == NULL ? g_strdup(dp->d_name) :
				g_strdup_printf("%s"G_DIR_SEPARATOR_S"%s", dir, dp->d_name);
			list = list_add_file(list, name, default_path);
			g_free(name);
		}
	}
	closedir(dirp);
	g_free(basename);

	g_free_not_null(dir);
        return list;
}

static GList *completion_get_settings(const char *key, SettingType type)
{
	GList *complist;
	GSList *tmp, *sets;
	int len;

	g_return_val_if_fail(key != NULL, NULL);

	sets = settings_get_sorted();

	len = strlen(key);
	complist = NULL;
	for (tmp = sets; tmp != NULL; tmp = tmp->next) {
		SETTINGS_REC *rec = tmp->data;

		if ((type == SETTING_TYPE_ANY || rec->type == type) && g_ascii_strncasecmp(rec->key, key, len) == 0)
			complist = g_list_insert_sorted(complist, g_strdup(rec->key),
			                                (GCompareFunc) i_istr_cmp);
	}
	g_slist_free(sets);
	return complist;
}

static GList *completion_get_aliases(const char *alias, char cmdchar)
{
	CONFIG_NODE *node;
	GList *complist;
	GSList *tmp;
	char *word;
	int len;

	g_return_val_if_fail(alias != NULL, NULL);

	/* get list of aliases from mainconfig */
	node = iconfig_node_traverse("aliases", FALSE);
	tmp = node == NULL ? NULL : config_node_first(node->value);

	len = strlen(alias);
	complist = NULL;
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		CONFIG_NODE *node = tmp->data;

		if (node->type != NODE_TYPE_KEY)
			continue;

		if (g_ascii_strncasecmp(node->key, alias, len) == 0) {
			word = cmdchar == '\0' ? g_strdup(node->key) :
				g_strdup_printf("%c%s", cmdchar, node->key);
			/* add matching alias to completion list, aliases will
			   be appended after command completions and kept in
			   uppercase to show it's an alias */
			if (i_list_find_icase_string(complist, word) == NULL)
				complist =
				    g_list_insert_sorted(complist, word, (GCompareFunc) i_istr_cmp);
			else
				g_free(word);
		}
	}
	return complist;
}

static GList *completion_get_commands(const char *cmd, char cmdchar)
{
	GList *complist;
	GSList *tmp;
	char *word;
	int len;

	g_return_val_if_fail(cmd != NULL, NULL);

	len = strlen(cmd);
	complist = NULL;
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (strchr(rec->cmd, ' ') != NULL)
			continue;

		if (g_ascii_strncasecmp(rec->cmd, cmd, len) == 0) {
			word = cmdchar == '\0' ? g_strdup(rec->cmd) :
				g_strdup_printf("%c%s", cmdchar, rec->cmd);
			if (i_list_find_icase_string(complist, word) == NULL)
				complist =
				    g_list_insert_sorted(complist, word, (GCompareFunc) i_istr_cmp);
			else
				g_free(word);
		}
	}
	return complist;
}

static GList *completion_get_subcommands(const char *cmd)
{
	GList *complist;
	GSList *tmp;
	char *spacepos;
	int len, skip;

	g_return_val_if_fail(cmd != NULL, NULL);

	/* get the number of chars to skip at the start of command. */
	spacepos = strrchr(cmd, ' ');
	skip = spacepos == NULL ? strlen(cmd)+1 :
		((int) (spacepos-cmd) + 1);

	len = strlen(cmd);
	complist = NULL;
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if ((int)strlen(rec->cmd) < len)
			continue;

		if (strchr(rec->cmd+len, ' ') != NULL)
			continue;

		if (g_ascii_strncasecmp(rec->cmd, cmd, len) == 0)
			complist = g_list_insert_sorted(complist, g_strdup(rec->cmd + skip),
			                                (GCompareFunc) i_istr_cmp);
	}
	return complist;
}

static GList *completion_get_options(const char *cmd, const char *option)
{
	COMMAND_REC *rec;
	GList *list;
	char **tmp;
	int len;

	g_return_val_if_fail(cmd != NULL, NULL);
	g_return_val_if_fail(option != NULL, NULL);

	rec = command_find(cmd);
	if (rec == NULL || rec->options == NULL) return NULL;

	list = NULL;
	len = strlen(option);
	for (tmp = rec->options; *tmp != NULL; tmp++) {
		const char *optname;
		if (**tmp == '~')
			continue; /* deprecated or hidden option */

		optname = *tmp + iscmdtype(**tmp);

		if (len == 0 || g_ascii_strncasecmp(optname, option, len) == 0)
                        list = g_list_append(list, g_strconcat("-", optname, NULL));
	}

	return list;
}

/* split the line to command and arguments */
static char *line_get_command(const char *line, char **args, int aliases)
{
	const char *ptr, *cmdargs;
	char *cmd, *checkcmd;

	g_return_val_if_fail(line != NULL, NULL);
	g_return_val_if_fail(args != NULL, NULL);

	cmd = checkcmd = NULL; *args = "";
	cmdargs = NULL; ptr = line;

	do {
		ptr = strchr(ptr, ' ');
		if (ptr == NULL) {
			checkcmd = g_strdup(line);
			cmdargs = "";
		} else {
			checkcmd = g_strndup(line, (int) (ptr-line));

			while (*ptr == ' ') ptr++;
			cmdargs = ptr;
		}

		if (aliases ? !alias_find(checkcmd) :
		    !command_find(checkcmd)) {
			/* not found, use the previous */
			g_free(checkcmd);
			break;
		}

		/* found, check if it has subcommands */
		g_free_not_null(cmd);
		if (!aliases)
			cmd = checkcmd;
		else {
                        cmd = g_strdup(alias_find(checkcmd));
			g_free(checkcmd);
		}
		*args = (char *) cmdargs;
	} while (ptr != NULL);

        if (cmd != NULL)
		ascii_strdown(cmd);
	return cmd;
}

static char *expand_aliases(const char *line)
{
        char *cmd, *args, *ret;

	g_return_val_if_fail(line != NULL, NULL);

	cmd = line_get_command(line, &args, TRUE);
	if (cmd == NULL) return g_strdup(line);
	if (*args == '\0') return cmd;

	ret = g_strconcat(cmd, " ", args, NULL);
	g_free(cmd);
	return ret;
}

static void sig_complete_word(GList **list, WINDOW_REC *window,
			      const char *word, const char *linestart,
			      int *want_space)
{
	const char *newword, *cmdchars;
	char *signal, *cmd, *args, *line;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(linestart != NULL);

	/* check against "completion words" list */
	newword = completion_find(word, FALSE);
	if (newword != NULL) {
		*list = g_list_append(*list, g_strdup(newword));

		signal_stop();
		return;
	}

	if (*linestart != '\0' && (*word == '/' || *word == '~')) {
		/* quite likely filename completion */
		*list = g_list_concat(*list, filename_complete(word, NULL));
		if (*list != NULL) {
			*want_space = FALSE;
			signal_stop();
			return;
		}
	}

	/* command completion? */
	cmdchars = settings_get_str("cmdchars");
	if (*word != '\0' && ((*linestart == '\0' && strchr(cmdchars, *word)) ||
			      (*linestart != '\0' && linestart[1] == '\0' &&
			       strchr(cmdchars, *linestart)))) {
		gboolean skip = *linestart == '\0' ? TRUE : FALSE;

		/* complete /command */
		*list = completion_get_commands(word + (skip ? 1 : 0),
						skip ? *word : '\0');

		/* complete aliases, too */
		*list = g_list_concat(*list,
				      completion_get_aliases(word + (skip ? 1 : 0),
							     skip ? *word : '\0'));

		if (*list != NULL) signal_stop();
		return;
	}

	/* check only for /command completions from now on */
	if (*linestart == '\0')
		return;

        cmdchars = strchr(cmdchars, *linestart);
	if (cmdchars == NULL) return;

        /* check if there's aliases */
	line = linestart[1] == *cmdchars ? g_strdup(linestart+2) :
		expand_aliases(linestart+1);

	cmd = line_get_command(line, &args, FALSE);
	if (cmd == NULL) {
		g_free(line);
		return;
	}

	/* we're completing -option? */
	if (*word == '-') {
		*list = completion_get_options(cmd, word+1);
		if (*list != NULL) signal_stop();
		g_free(cmd);
		g_free(line);
		return;
	}

	/* complete parameters */
	signal = g_strconcat("complete command ", cmd, NULL);
	signal_emit(signal, 5, list, window, word, args, want_space);

	if (command_have_sub(line)) {
		/* complete subcommand */
		g_free(cmd);
		cmd = g_strconcat(line, " ", word, NULL);
		*list = g_list_concat(completion_get_subcommands(cmd), *list);
	}

	if (*list != NULL) signal_stop();
	g_free(signal);
	g_free(cmd);
	g_free(line);
}

static void sig_complete_erase(WINDOW_REC *window, const char *word,
			       const char *linestart)
{
	const char *cmdchars;
        char *line, *cmd, *args, *signal;

	if (*linestart == '\0')
		return;

        /* we only want to check for commands */
	cmdchars = settings_get_str("cmdchars");
        cmdchars = strchr(cmdchars, *linestart);
	if (cmdchars == NULL)
		return;

        /* check if there's aliases */
	line = linestart[1] == *cmdchars ? g_strdup(linestart+2) :
		expand_aliases(linestart+1);

	cmd = line_get_command(line, &args, FALSE);
	if (cmd == NULL) {
		g_free(line);
		return;
	}

	signal = g_strconcat("complete erase command ", cmd, NULL);
	signal_emit(signal, 3, window, word, args);

        g_free(signal);
	g_free(cmd);
	g_free(line);
}

static void sig_complete_set(GList **list, WINDOW_REC *window,
			     const char *word, const char *line, int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line == '\0' ||
	    !g_strcmp0("-clear", line) || !g_strcmp0("-default", line))
		*list = completion_get_settings(word, SETTING_TYPE_ANY);
	else if (*line != '\0' && *word == '\0') {
		SETTINGS_REC *rec = settings_get_record(line);
		if (rec != NULL) {
			char *value = settings_get_print(rec);

			/* show the current option first */
			if (value != NULL)
				*list = g_list_append(*list, value);

			/* show the whole list of valid options */
			if (rec->type == SETTING_TYPE_CHOICE) {
				char **tmp;

				for (tmp = rec->choices; *tmp; tmp++) {
					if (g_ascii_strcasecmp(*tmp, value) != 0)
						*list = g_list_append(*list, g_strdup(*tmp));
				}
			}
		}
	}

	if (*list != NULL) signal_stop();
}

static void sig_complete_toggle(GList **list, WINDOW_REC *window,
				const char *word, const char *line, int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line != '\0') return;

	*list = completion_get_settings(word, SETTING_TYPE_BOOLEAN);
	if (*list != NULL) signal_stop();
}

/* first argument of command is file name - complete it */
static void sig_complete_filename(GList **list, WINDOW_REC *window,
				  const char *word, const char *line, int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line != '\0') return;

	*list = filename_complete(word, NULL);
	if (*list != NULL) {
		*want_space = FALSE;
		signal_stop();
	}
}

/* first argument of command is .. command :) (/HELP command) */
static void sig_complete_command(GList **list, WINDOW_REC *window,
				  const char *word, const char *line, int *want_space)
{
	char *cmd;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line == '\0') {
		/* complete base command */
		*list = completion_get_commands(word, '\0');
	} else if (command_have_sub(line)) {
		/* complete subcommand */
                cmd = g_strconcat(line, " ", word, NULL);
		*list = completion_get_subcommands(cmd);
		g_free(cmd);
	}

	if (*list != NULL) signal_stop();
}

/* SYNTAX: COMPLETION [-auto] [-delete] <key> <value> */
static void cmd_completion(const char *data)
{
	GHashTable *optlist;
	CONFIG_NODE *node;
	GSList *tmp;
	char *key, *value;
	void *free_arg;
	int len;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST,
			    "completion", &optlist, &key, &value))
		return;

	node = iconfig_node_traverse("completions", *value != '\0');
	if (node != NULL && node->type != NODE_TYPE_BLOCK) {
		/* FIXME: remove after 0.8.5 */
		iconfig_node_remove(mainconfig->mainnode, node);
		node = iconfig_node_traverse("completions", *value != '\0');
	}

	if (node == NULL || (node->value == NULL && *value == '\0')) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_NO_COMPLETIONS);
		cmd_params_free(free_arg);
		return;
	}

	if (g_hash_table_lookup(optlist, "delete") != NULL && *key != '\0') {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
			    TXT_COMPLETION_REMOVED, key);

		iconfig_set_str("completions", key, NULL);
		signal_emit("completion removed", 1, key);
	} else if (*key != '\0' && *value != '\0') {
		int automatic = g_hash_table_lookup(optlist, "auto") != NULL;

		node = iconfig_node_section(node, key, NODE_TYPE_BLOCK);
		iconfig_node_set_str(node, "value", value);
		if (automatic)
			iconfig_node_set_bool(node, "auto", TRUE);
		else
			iconfig_node_set_str(node, "auto", NULL);

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_COMPLETION_LINE,
			    key, value, automatic ? "yes" : "no");

		signal_emit("completion added", 1, key);
	} else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_COMPLETION_HEADER);

		len = strlen(key);
		for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
			node = tmp->data;

			if (len == 0 ||
			    g_ascii_strncasecmp(node->key, key, len) == 0) {
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
					    TXT_COMPLETION_LINE, node->key,
					    config_node_get_str(node, "value", ""),
					    config_node_get_bool(node, "auto", FALSE) ? "yes" : "no");
			}
		}

		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    TXT_COMPLETION_FOOTER);
	}

	cmd_params_free(free_arg);
}

void completion_init(void)
{
	complist = NULL;
	last_line = NULL; last_line_pos = -1;

	chat_completion_init();

	settings_add_bool("completion", "completion_keep_word", TRUE);
	command_bind("completion", NULL, (SIGNAL_FUNC) cmd_completion);

	signal_add_first("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_add_first("complete erase", (SIGNAL_FUNC) sig_complete_erase);
	signal_add("complete command set", (SIGNAL_FUNC) sig_complete_set);
	signal_add("complete command toggle", (SIGNAL_FUNC) sig_complete_toggle);
	signal_add("complete command load", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command cat", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command save", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command reload", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command rawlog open", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command rawlog save", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command help", (SIGNAL_FUNC) sig_complete_command);

	command_set_options("completion", "auto delete");
}

void completion_deinit(void)
{
        free_completions();

	chat_completion_deinit();

	command_unbind("completion", (SIGNAL_FUNC) cmd_completion);

	signal_remove("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_remove("complete erase", (SIGNAL_FUNC) sig_complete_erase);
	signal_remove("complete command set", (SIGNAL_FUNC) sig_complete_set);
	signal_remove("complete command toggle", (SIGNAL_FUNC) sig_complete_toggle);
	signal_remove("complete command load", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command cat", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command save", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command reload", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command rawlog open", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command rawlog save", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command help", (SIGNAL_FUNC) sig_complete_command);
}
