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
#include "lib-config/iconfig.h"
#include "settings.h"

#include "completion.h"

#define wordreplace_find(replace) \
	iconfig_list_find("replaces", "text", replace, "replace")

#define completion_find(completion) \
	iconfig_list_find("completions", "short", completion, "long")

static GList *complist; /* list of commands we're currently completing */
static char *last_linestart;

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
	int startpos, wordlen;

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
	} else {
		/* get new completion list */
		free_completions();

		last_linestart = g_strdup(linestart);
		signal_emit("word complete", 4, window, word, linestart, &complist);
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

		if (!isseparator(result->str[*pos-1]))
			g_string_insert_c(result, *pos-1, ' ');

		ret = result->str;
		g_string_free(result, FALSE);
	}

	g_free(linestart);
	g_free(word);
	return ret;
}

static int is_sub_command(const char *command)
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
			complist = g_list_append(complist, g_strdup(rec->key));
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
				complist = g_list_append(complist, word);
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
			complist = g_list_append(complist, g_strdup(rec->cmd+skip));
	}
	return complist;
}

static void sig_word_complete(WINDOW_REC *window, const char *word,
			      const char *linestart, GList **list)
{
	const char *newword, *cmdchars;

	g_return_if_fail(word != NULL);

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

	if (strchr(cmdchars, *linestart) && is_sub_command(linestart+1)) {
		/* complete (/command's) subcommand */
		char *tmp;

                tmp = g_strconcat(linestart+1, " ", word, NULL);
		*list = completion_get_subcommands(tmp);
		g_free(tmp);

		if (*list != NULL) signal_stop();
		return;
	}
}

void completion_init(void)
{
	complist = NULL;
	last_linestart = NULL;

	signal_add("word complete", (SIGNAL_FUNC) sig_word_complete);
}

void completion_deinit(void)
{
        free_completions();

	signal_remove("word complete", (SIGNAL_FUNC) sig_word_complete);
}
