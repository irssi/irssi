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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "completion.h"

#define wordreplace_find(replace) \
	iconfig_list_find("replaces", "text", replace, "replace")

#define completion_find(completion) \
	iconfig_list_find("completions", "short", completion, "long")

static GList *complist; /* list of commands we're currently completing */
static char *last_linestart;
static int last_want_space;

#define isseparator_notspace(c) \
        ((c) == ',')

#define isseparator(c) \
	(isspace((int) (c)) || isseparator_notspace(c))

/* Return whole word at specified position in string */
char *get_word_at(const char *str, int pos, char **startpos)
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
	replace = wordreplace_find(word);
	if (replace == NULL) {
		ret = NULL;
		g_string_free(result, TRUE);
	} else {
		*pos = startpos+strlen(replace);

		g_string_insert(result, startpos, replace);
		ret = result->str;
		g_string_free(result, FALSE);
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

	g_free_and_null(last_linestart);
}

/* manual word completion - called when TAB is pressed */
char *word_complete(WINDOW_REC *window, const char *line, int *pos)
{
	GString *result;
	char *word, *wordstart, *linestart, *ret;
	int startpos, wordlen, want_space;

	g_return_val_if_fail(line != NULL, NULL);
	g_return_val_if_fail(pos != NULL, NULL);

	/* get the word we want to complete */
	word = get_word_at(line, *pos, &wordstart);
	startpos = (int) (wordstart-line);
	wordlen = strlen(word);

	/* get the start of line until the word we're completing */
	while (wordstart > line && isseparator(wordstart[-1])) wordstart--;
	linestart = g_strndup(line, (int) (wordstart-line));

	if (complist != NULL && strcmp(linestart, last_linestart) == 0 &&
	    g_strcasecmp(complist->data, word) == 0) {
		/* complete from old list */
		complist = complist->next != NULL ? complist->next :
			g_list_first(complist);
		want_space = last_want_space;
	} else {
		/* get new completion list */
		free_completions();

		last_linestart = g_strdup(linestart);
		want_space = TRUE;
		signal_emit("complete word", 5, &complist, window, word, linestart, &want_space);
		last_want_space = want_space;
	}

	if (complist == NULL)
		ret = NULL;
	else {
		/* word completed */
		*pos = startpos+strlen(complist->data)+1;

		/* replace the word in line - we need to return
		   a full new line */
		result = g_string_new(line);
		g_string_erase(result, startpos, wordlen);
		g_string_insert(result, startpos, complist->data);

		if (want_space && !isseparator(result->str[*pos-1]))
			g_string_insert_c(result, *pos-1, ' ');

		ret = result->str;
		g_string_free(result, FALSE);
	}

	g_free(linestart);
	g_free(word);
	return ret;
}

GList *list_add_file(GList *list, const char *name)
{
	struct stat statbuf;
	char *fname;

	fname = convert_home(name);
	if (stat(fname, &statbuf) == 0) {
		list = g_list_append(list, !S_ISDIR(statbuf.st_mode) ? g_strdup(name) :
				     g_strconcat(name, G_DIR_SEPARATOR_S, NULL));
	}

        g_free(fname);
	return list;
}

GList *filename_complete(const char *path)
{
        GList *list;
	DIR *dirp;
	struct dirent *dp;
	char *realpath, *dir, *basename, *name;
	int len;

	list = NULL;

	/* get directory part of the path - expand ~/ */
	realpath = convert_home(path);
	dir = g_dirname(realpath);
	g_free(realpath);

	/* open directory for reading */
	dirp = opendir(dir);
	g_free(dir);
	if (dirp == NULL) return NULL;

	dir = g_dirname(path);
	basename = g_basename(path);
	len = strlen(basename);

	/* add all files in directory to completion list */
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.') {
			if (dp->d_name[1] == '\0' ||
			    (dp->d_name[1] == '.' && dp->d_name[2] == '\0'))
				continue; /* skip . and .. */

			if (basename[0] != '.')
				continue;
		}

		if (len == 0 || strncmp(dp->d_name, basename, len) == 0) {
			name = g_strdup_printf("%s"G_DIR_SEPARATOR_S"%s", dir, dp->d_name);
			list = list_add_file(list, name);
			g_free(name);
		}
	}
	closedir(dirp);

	g_free(dir);
        return list;
}

static int is_base_command(const char *command)
{
	GSList *tmp;
	int len;

	/* find "command "s */
        len = strlen(command);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (g_strncasecmp(rec->cmd, command, len) == 0 && rec->cmd[len] == ' ')
			return TRUE;
	}

	return FALSE;
}

static GList *completion_get_settings(const char *key)
{
	GList *complist;
	GSList *tmp, *sets;
	int len;

	sets = settings_get_sorted();

	len = strlen(key);
	complist = NULL;
	for (tmp = sets; tmp != NULL; tmp = tmp->next) {
		SETTINGS_REC *rec = tmp->data;

		if (g_strncasecmp(rec->key, key, len) == 0)
			complist = g_list_insert_sorted(complist, g_strdup(rec->key), (GCompareFunc) g_istr_cmp);
	}
	g_slist_free(sets);
	return complist;
}

static GList *completion_get_commands(const char *cmd, char cmdchar)
{
	GList *complist;
	GSList *tmp;
	char *word;
	int len;

	len = strlen(cmd);
	complist = NULL;
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (strchr(rec->cmd, ' ') != NULL)
			continue;

		if (g_strncasecmp(rec->cmd, cmd, len) == 0) {
			word = g_strdup_printf("%c%s", cmdchar, rec->cmd);
			if (glist_find_icase_string(complist, word) == NULL)
				complist = g_list_insert_sorted(complist, word, (GCompareFunc) g_istr_cmp);
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

	/* get the number of chars to skip at the start of command. */
	spacepos = strrchr(cmd, ' ');
	skip = spacepos == NULL ? 0 :
		((int) (spacepos-cmd) + 1);

	len = strlen(cmd);
	complist = NULL;
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		COMMAND_REC *rec = tmp->data;

		if (strlen(rec->cmd) < len)
			continue;

		if (strchr(rec->cmd+len, ' ') != NULL)
			continue;

		if (g_strncasecmp(rec->cmd, cmd, len) == 0)
			complist = g_list_insert_sorted(complist, g_strdup(rec->cmd+skip), (GCompareFunc) g_istr_cmp);
	}
	return complist;
}

/* split the line to command and arguments */
static char *line_get_command(const char *line, char **args)
{
	const char *ptr, *cmdargs;
	char *cmd, *checkcmd;

	cmd = checkcmd = NULL;
	cmdargs = NULL; ptr = line;

	do {
		ptr = strchr(ptr, ' ');
		if (ptr == NULL) {
			checkcmd = g_strdup(line);
			cmdargs = "";
		} else {
			checkcmd = g_strndup(line, (int) (ptr-line));

			while (isspace(*ptr)) ptr++;
			cmdargs = ptr;
		}

		if (!command_find(checkcmd)) {
			/* not found, use the previous */
			g_free(checkcmd);
			break;
		}

		/* found, check if it has subcommands */
		g_free_not_null(cmd);
		cmd = checkcmd;
		*args = (char *) cmdargs;
	} while (ptr != NULL);

	return cmd;
}

static void sig_complete_word(GList **list, WINDOW_REC *window,
			      const char *word, const char *linestart, int *want_space)
{
	const char *newword, *cmdchars;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(linestart != NULL);

	/* check against "completion words" list */
	newword = completion_find(word);
	if (newword != NULL) {
		*list = g_list_append(*list, g_strdup(newword));

		signal_stop();
		return;
	}

	/* /SET variable name completion */
	if (g_strcasecmp(linestart, "/SET") == 0) {
		*list = completion_get_settings(word);

		if (*list != NULL) signal_stop();
		return;
	}

	/* command completion? */
	cmdchars = settings_get_str("cmdchars");
	if (strchr(cmdchars, *word) && *linestart == '\0') {
		/* complete /command */
		*list = completion_get_commands(word+1, *word);

		if (*list != NULL) signal_stop();
		return;
	}

	if (strchr(cmdchars, *linestart) && is_base_command(linestart+1)) {
		/* complete /command's subcommand */
		char *tmp;

                tmp = g_strconcat(linestart+1, " ", word, NULL);
		*list = completion_get_subcommands(tmp);
		g_free(tmp);

		if (*list != NULL) signal_stop();
		return;
	}

	if (strchr(cmdchars, *linestart)) {
		/* complete /command's parameters */
		char *signal, *cmd, *args;

		cmd = line_get_command(linestart+1, &args);
		if (cmd != NULL) {
			signal = g_strconcat("complete command ", cmd, NULL);
			signal_emit(signal, 5, list, window, word, args, want_space);

			g_free(signal);
			g_free(cmd);
		}
	}
}

/* first argument of command is file name - complete it */
static void sig_complete_filename(GList **list, WINDOW_REC *window,
				  const char *word, const char *line, int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line != '\0') return;

	*list = filename_complete(word);
	if (*list != NULL) {
		*want_space = FALSE;
		signal_stop();
	}
}

void completion_init(void)
{
	complist = NULL;
	last_linestart = NULL;

	signal_add("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_add("complete command cat", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command run", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command save", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command rehash", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command rawlog open", (SIGNAL_FUNC) sig_complete_filename);
	signal_add("complete command rawlog save", (SIGNAL_FUNC) sig_complete_filename);
}

void completion_deinit(void)
{
        free_completions();

	signal_remove("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_remove("complete command cat", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command run", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command save", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command rehash", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command rawlog open", (SIGNAL_FUNC) sig_complete_filename);
	signal_remove("complete command rawlog save", (SIGNAL_FUNC) sig_complete_filename);
}
