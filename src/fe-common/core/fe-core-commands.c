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

#include "windows.h"

static const char *ret_texts[] = {
        NULL,
	"Not enough parameters given",
	"Not connected to IRC server yet",
	"Not joined to any channels yet",
	"Not joined to such channel",
	"Channel not fully synchronized yet, try again after a while",
	"Doing this is not a good idea. Add -YES if you really mean it",
};

/* keep the whole command line here temporarily. we need it in
   "default command" event handler, but there we don't know if the start of
   the line had one or two command chars, and which one.. */
static const char *current_cmdline;

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
    COMMAND_REC *rec, *last;
    GString *str;
    GSList *tmp;
    gint lines, cols, line, col, skip;
    gchar *cmdbuf;

    str = g_string_new(NULL);

    cols = max > 65 ? 1 : (65 / max);
    lines = items <= cols ? 1 : items / cols+1;

    last = NULL; cmdbuf = g_malloc(max+1); cmdbuf[max] = '\0';
    for (line = 0, col = 0, skip = 1, tmp = cmdlist; line < lines; last = rec, tmp = tmp->next)
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
	    printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, str->str);
	    g_string_truncate(str, 0);
	    col = 0; line++;
	    tmp = g_slist_nth(cmdlist, line-1); skip = 1;
	}
    }
    if (str->len != 0)
	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, str->str);
    g_string_free(str, TRUE);
    g_free(cmdbuf);
}

static int show_help(COMMAND_REC *cmd)
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
        if (ret > 0) printtext(NULL, NULL, MSGLEVEL_NEVER, str);
    }
    while (ret > 0);
    line_split_free(buffer);

    close(f);
    return TRUE;
}

static void cmd_help(gchar *data)
{
    COMMAND_REC *rec, *last, *helpitem;
    GSList *tmp, *cmdlist;
    gint len, max, items, findlen;
    gboolean header;

    g_return_if_fail(data != NULL);

    /* sort the commands list */
    commands = g_slist_sort(commands, (GCompareFunc) commands_compare);

    /* print command, sort by category */
    cmdlist = NULL; last = NULL; header = FALSE; helpitem = NULL;
    max = items = 0; findlen = strlen(data);
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

	if (strlen(rec->cmd) >= findlen && g_strncasecmp(rec->cmd, data, findlen) == 0)
	{
	    if (rec->cmd[findlen] == '\0')
	    {
		helpitem = rec;
		break;
	    }
	    else if (strchr(rec->cmd+findlen+1, ' ') == NULL)
	    {
		/* not a subcommand (and matches the query) */
		len = strlen(rec->cmd);
		if (max < len) max = len;
		items++;
		cmdlist = g_slist_append(cmdlist, rec);
	    }
	}
    }

    if ((helpitem == NULL && items == 0) || (helpitem != NULL && !show_help(helpitem)))
	printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "No help for %s", data);

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

static void cmd_echo(const char *data, void *server, WI_ITEM_REC *item)
{
	g_return_if_fail(data != NULL);

	printtext(server, item == NULL ? NULL : item->name, MSGLEVEL_CRAP, "%s", data);
}

static void cmd_version(char *data)
{
	g_return_if_fail(data != NULL);

	if (*data == '\0')
		printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "Client: "PACKAGE" " IRSSI_VERSION);
}

static void cmd_cat(const char *data)
{
	char *params, *fname, *fposstr;
	char tmpbuf[1024], *str;
	LINEBUF_REC *buffer = NULL;
	int f, ret, recvlen, fpos;

	params = cmd_get_params(data, 2, &fname, &fposstr);
	fname = convert_home(fname);
	fpos = atoi(fposstr);
	g_free(params);

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

static void cmd_beep(void)
{
	printbeep();
}

static void cmd_unknown(const char *data, void *server, WI_ITEM_REC *item)
{
	char *cmd;

	cmd = g_strdup(data); g_strup(cmd);
	printtext(server, item == NULL ? NULL : item->name, MSGLEVEL_CRAP, "Unknown command: %s", cmd);
	g_free(cmd);

	signal_stop();
}

static void event_command(const char *data)
{
        current_cmdline = data;
}

static void event_default_command(const char *data, void *server, WI_ITEM_REC *item)
{
	const char *cmd;

	cmd = data;
	while (*cmd != '\0' && *cmd != ' ') {
		if (strchr(settings_get_str("cmdchars"), *cmd)) {
			/* command character inside command .. we probably
			   want to send this text to channel. for example
			   when pasting a path /usr/bin/xxx. */
			signal_emit("send text", 3, current_cmdline, server, item);
			return;
		}
		cmd++;
	}

	cmd_unknown(data, server, item);
}

static void event_cmderror(gpointer errorp)
{
	int error;

	error = GPOINTER_TO_INT(errorp);
        if (error == CMDERR_ERRNO)
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, g_strerror(errno));
	else
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, ret_texts[error]);
}

void fe_core_commands_init(void)
{
	command_bind("help", NULL, (SIGNAL_FUNC) cmd_help);
	command_bind("echo", NULL, (SIGNAL_FUNC) cmd_echo);
	command_bind("version", NULL, (SIGNAL_FUNC) cmd_version);
	command_bind("cat", NULL, (SIGNAL_FUNC) cmd_cat);
	command_bind("beep", NULL, (SIGNAL_FUNC) cmd_beep);

	signal_add("unknown command", (SIGNAL_FUNC) cmd_unknown);
	signal_add("send command", (SIGNAL_FUNC) event_command);
	signal_add("default command", (SIGNAL_FUNC) event_default_command);
	signal_add("error command", (SIGNAL_FUNC) event_cmderror);
}

void fe_core_commands_deinit(void)
{
	command_unbind("help", (SIGNAL_FUNC) cmd_help);
	command_unbind("echo", (SIGNAL_FUNC) cmd_echo);
	command_unbind("version", (SIGNAL_FUNC) cmd_version);
	command_unbind("cat", (SIGNAL_FUNC) cmd_cat);
	command_unbind("beep", (SIGNAL_FUNC) cmd_beep);

	signal_remove("unknown command", (SIGNAL_FUNC) cmd_unknown);
	signal_remove("send command", (SIGNAL_FUNC) event_command);
	signal_remove("default command", (SIGNAL_FUNC) event_default_command);
	signal_remove("error command", (SIGNAL_FUNC) event_cmderror);
}
