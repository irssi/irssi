/*
 fe-core-commands.c : irssi

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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "line-split.h"
#include "settings.h"
#include "irssi-version.h"

#include "fe-windows.h"
#include "printtext.h"

#define PASTE_CHECK_SPEED 200 /* 0.2 sec */

static int ret_texts[] = {
	IRCTXT_OPTION_UNKNOWN,
	IRCTXT_OPTION_AMBIGUOUS,
	IRCTXT_OPTION_MISSING_ARG,
	IRCTXT_COMMAND_UNKNOWN,
	IRCTXT_COMMAND_AMBIGUOUS,
        -1,
	IRCTXT_NOT_ENOUGH_PARAMS,
	IRCTXT_NOT_CONNECTED,
	IRCTXT_NOT_JOINED,
	IRCTXT_CHAN_NOT_FOUND,
	IRCTXT_CHAN_NOT_SYNCED,
	IRCTXT_NOT_GOOD_IDEA
};

/* keep the whole command line here temporarily. we need it in
   "default command" event handler, but there we don't know if the start of
   the line had one or two command chars, and which one.. */
static const char *current_cmdline;
static int hide_output;

static GTimeVal time_command_last, time_command_now;
static int last_command_cmd, command_cmd;

static int commands_compare(COMMAND_REC *rec, COMMAND_REC *rec2)
{
	if (rec->category == NULL && rec2->category != NULL)
		return -1;
	if (rec2->category == NULL && rec->category != NULL)
		return 1;

	return strcmp(rec->cmd, rec2->cmd);
}

static void help_category(GSList *cmdlist, gint items, gint max)
{
    COMMAND_REC *rec;
    GString *str;
    GSList *tmp;
    gint lines, cols, line, col, skip;
    gchar *cmdbuf;

    str = g_string_new(NULL);

    cols = max > 65 ? 1 : (65 / max);
    lines = items <= cols ? 1 : items / cols+1;

    cmdbuf = g_malloc(max+1); cmdbuf[max] = '\0';
    for (line = 0, col = 0, skip = 1, tmp = cmdlist; line < lines; tmp = tmp->next)
    {
	rec = tmp->data;

	if (--skip == 0)
	{
	    skip = lines;
	    memset(cmdbuf, ' ', max);
	    memcpy(cmdbuf, rec->cmd, strlen(rec->cmd));
	    g_string_sprintfa(str, "%s ", cmdbuf);
	    cols++;
	}

	if (col == cols || tmp->next == NULL)
	{
	    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s", str->str);
	    g_string_truncate(str, 0);
	    col = 0; line++;
	    tmp = g_slist_nth(cmdlist, line-1); skip = 1;
	}
    }
    if (str->len != 0)
	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s", str->str);
    g_string_free(str, TRUE);
    g_free(cmdbuf);
}

static int show_help_rec(COMMAND_REC *cmd)
{
    char tmpbuf[1024], *str, *path;
    LINEBUF_REC *buffer = NULL;
    int f, ret, recvlen;

    /* helpdir/command or helpdir/category/command */
    if (cmd->category == NULL)
	path = g_strdup_printf("%s/%s", HELPDIR, cmd->cmd);
    else
	path = g_strdup_printf("%s/%s/%s", HELPDIR, cmd->category, cmd->cmd);
    f = open(path, O_RDONLY);
    g_free(path);

    if (f == -1)
	return FALSE;

    /* just print to screen whatever is in the file */
    do
    {
	recvlen = read(f, tmpbuf, sizeof(tmpbuf));

	ret = line_split(tmpbuf, recvlen, &str, &buffer);
        if (ret > 0) printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s", str);
    }
    while (ret > 0);
    line_split_free(buffer);

    close(f);
    return TRUE;
}

static void show_help(const char *data)
{
    COMMAND_REC *rec, *last, *helpitem;
    GSList *tmp, *cmdlist;
    gint len, max, items, findlen;
    gboolean header, found;

    g_return_if_fail(data != NULL);

    /* sort the commands list */
    commands = g_slist_sort(commands, (GCompareFunc) commands_compare);

    /* print command, sort by category */
    cmdlist = NULL; last = NULL; header = FALSE; helpitem = NULL;
    max = items = 0; findlen = strlen(data); found = FALSE;
    for (tmp = commands; tmp != NULL; last = rec, tmp = tmp->next)
    {
	rec = tmp->data;

	if (last != NULL && rec->category != NULL &&
	    (last->category == NULL || strcmp(rec->category, last->category) != 0))
	{
	    /* category changed */
	    if (items > 0)
	    {
		if (!header)
		{
		    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "Irssi commands:");
		    header = TRUE;
		}
		if (last->category != NULL)
		{
		    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "");
		    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s:", last->category);
		}
		help_category(cmdlist, items, max);
	    }

	    g_slist_free(cmdlist); cmdlist = NULL;
	    items = 0; max = 0;
	}

	if (last != NULL && g_strcasecmp(rec->cmd, last->cmd) == 0)
	    continue; /* don't display same command twice */

	if ((int)strlen(rec->cmd) >= findlen && 
		g_strncasecmp(rec->cmd, data, findlen) == 0)
	{
	    if (rec->cmd[findlen] == '\0')
	    {
		helpitem = rec;
                found = TRUE;
		break;
	    }
	    else if (strchr(rec->cmd+findlen+1, ' ') == NULL)
	    {
		/* not a subcommand (and matches the query) */
		len = strlen(rec->cmd);
		if (max < len) max = len;
		items++;
		cmdlist = g_slist_append(cmdlist, rec);
		found = TRUE;
	    }
	}
    }

    if (!found || (helpitem != NULL && !show_help_rec(helpitem)))
	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "No help for %s", data);

    if (data[strlen(data)-1] != ' ' && command_have_sub(data)) {
	    char *cmd;

	    cmd = g_strconcat(data, " ", NULL);
	    show_help(cmd);
	    g_free(cmd);
    }

    if (items != 0)
    {
	/* display the last category */
	if (!header)
	{
	    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "Irssi commands:");
	    header = TRUE;
	}

	if (last->category != NULL)
	{
	    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "");
	    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s:", last->category);
	}
	help_category(cmdlist, items, max);
	g_slist_free(cmdlist);
    }
}

/* SYNTAX: HELP [<command>] */
static void cmd_help(const char *data)
{
	char *cmd, *ptr;

	cmd = g_strdup(data);
	ptr = cmd+strlen(cmd);
	while (ptr[-1] == ' ') ptr--; *ptr = '\0';

	show_help(cmd);
        g_free(cmd);
}

/* SYNTAX: ECHO [-current] [-window <name>] [-level <level>] <text> */
static void cmd_echo(const char *data, void *server, WI_ITEM_REC *item)
{
        WINDOW_REC *window;
	GHashTable *optlist;
	char *msg, *levelstr, *winname;
	void *free_arg;
	int level;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST, "echo", &optlist, &msg))
		return;

        levelstr = g_hash_table_lookup(optlist, "level");
	level = levelstr == NULL ? 0 :
		level2bits(g_hash_table_lookup(optlist, "level"));
	if (level == 0) level = MSGLEVEL_CRAP;

	winname = g_hash_table_lookup(optlist, "window");
	window = winname == NULL ? NULL :
		is_numeric(winname, '\0') ?
		window_find_refnum(atoi(winname)) :
		window_find_item(NULL, winname);
	if (window == NULL) window = active_win;

	printtext_window(window, level, "%s", msg);
	cmd_params_free(free_arg);
}

/* SYNTAX: VERSION */
static void cmd_version(char *data)
{
	g_return_if_fail(data != NULL);

	if (*data == '\0')
		printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "Client: "PACKAGE" " IRSSI_VERSION);
}

/* SYNTAX: CAT <file> */
static void cmd_cat(const char *data)
{
	LINEBUF_REC *buffer = NULL;
	char *fname, *fposstr;
	char tmpbuf[1024], *str;
	void *free_arg;
	int f, ret, recvlen, fpos;

	if (!cmd_get_params(data, &free_arg, 2, &fname, &fposstr))
		return;

	fname = convert_home(fname);
	fpos = atoi(fposstr);
        cmd_params_free(free_arg);

	f = open(fname, O_RDONLY);
	g_free(fname);

	if (f == -1) {
		/* file not found */
                printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", g_strerror(errno));
		return;
	}

        lseek(f, fpos, SEEK_SET);
	do {
		recvlen = read(f, tmpbuf, sizeof(tmpbuf));

		ret = line_split(tmpbuf, recvlen, &str, &buffer);
		if (ret > 0) printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s", str);
	} while (ret > 0);
	line_split_free(buffer);

	close(f);
}

/* SYNTAX: BEEP */
static void cmd_beep(void)
{
	printbeep();
}

static void sig_stop(void)
{
	signal_stop();
}

static void event_command(const char *data)
{
	const char *cmdchar;

	/* save current command line */
	current_cmdline = data;

        /* for detecting if we're pasting text */
	time_command_last = time_command_now;
	last_command_cmd = command_cmd;

	g_get_current_time(&time_command_now);
	command_cmd = strchr(settings_get_str("cmdchars"), *data) != NULL;

	/* /^command hides the output of the command */
	cmdchar = strchr(settings_get_str("cmdchars"), *data);
	if (cmdchar != NULL && (data[1] == '^' || (data[1] == *cmdchar && data[2] == '^'))) {
                hide_output = TRUE;
		signal_add_first("print starting", (SIGNAL_FUNC) sig_stop);
		signal_add_first("print format", (SIGNAL_FUNC) sig_stop);
		signal_add_first("print text stripped", (SIGNAL_FUNC) sig_stop);
		signal_add_first("print text", (SIGNAL_FUNC) sig_stop);
	}
}

static void event_command_last(const char *data)
{
	if (hide_output) {
		hide_output = FALSE;
		signal_remove("print starting", (SIGNAL_FUNC) sig_stop);
		signal_remove("print format", (SIGNAL_FUNC) sig_stop);
		signal_remove("print text stripped", (SIGNAL_FUNC) sig_stop);
		signal_remove("print text", (SIGNAL_FUNC) sig_stop);
	}
}

static void event_default_command(const char *data, void *server, WI_ITEM_REC *item)
{
	const char *cmdchars, *ptr;
	char *cmd, *p;
	long diff;

	cmdchars = settings_get_str("cmdchars");

	ptr = data;
	while (*ptr != '\0' && *ptr != ' ') {
		if (strchr(cmdchars, *ptr)) {
			/* command character inside command .. we probably
			   want to send this text to channel. for example
			   when pasting a path /usr/bin/xxx. */
			signal_emit("send text", 3, current_cmdline, server, item);
			return;
		}
		ptr++;
	}

	/* maybe we're copy+pasting text? check how long it was since the
	   last line */
	diff = get_timeval_diff(&time_command_now, &time_command_last);
	if (item != NULL && !last_command_cmd && diff < PASTE_CHECK_SPEED) {
		signal_emit("send text", 3, current_cmdline, active_win->active_server, active_win->active);
		command_cmd = FALSE;
		return;
	}

	/* get the command part of the line, send "error command" signal */
	cmd = g_strdup(data);
	p = strchr(cmd, ' ');
	if (p != NULL) *p = '\0';

	signal_emit("error command", 2, GINT_TO_POINTER(CMDERR_UNKNOWN), cmd);

	g_free(cmd);
}

static void event_cmderror(gpointer errorp, const char *arg)
{
	int error;

	error = GPOINTER_TO_INT(errorp);
	if (error == CMDERR_ERRNO) {
                /* errno is special */
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", g_strerror(errno));
	} else {
                /* others */
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, ret_texts[error + -CMDERR_OPTION_UNKNOWN], arg);
	}
}

void fe_core_commands_init(void)
{
	hide_output = FALSE;

	command_cmd = FALSE;
	memset(&time_command_now, 0, sizeof(GTimeVal));

	command_bind("help", NULL, (SIGNAL_FUNC) cmd_help);
	command_bind("echo", NULL, (SIGNAL_FUNC) cmd_echo);
	command_bind("version", NULL, (SIGNAL_FUNC) cmd_version);
	command_bind("cat", NULL, (SIGNAL_FUNC) cmd_cat);
	command_bind("beep", NULL, (SIGNAL_FUNC) cmd_beep);

	signal_add("send command", (SIGNAL_FUNC) event_command);
	signal_add_last("send command", (SIGNAL_FUNC) event_command_last);
	signal_add("default command", (SIGNAL_FUNC) event_default_command);
	signal_add("error command", (SIGNAL_FUNC) event_cmderror);

	command_set_options("echo", "current +level +window");
}

void fe_core_commands_deinit(void)
{
	command_unbind("help", (SIGNAL_FUNC) cmd_help);
	command_unbind("echo", (SIGNAL_FUNC) cmd_echo);
	command_unbind("version", (SIGNAL_FUNC) cmd_version);
	command_unbind("cat", (SIGNAL_FUNC) cmd_cat);
	command_unbind("beep", (SIGNAL_FUNC) cmd_beep);

	signal_remove("send command", (SIGNAL_FUNC) event_command);
	signal_remove("send command", (SIGNAL_FUNC) event_command_last);
	signal_remove("default command", (SIGNAL_FUNC) event_default_command);
	signal_remove("error command", (SIGNAL_FUNC) event_cmderror);
}
