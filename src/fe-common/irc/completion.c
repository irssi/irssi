/*
 completion.c : irssi

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
#include "signals.h"
#include "commands.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "irc.h"
#include "server.h"
#include "channels.h"
#include "nicklist.h"

#include "completion.h"
#include "window-items.h"

typedef struct {
	time_t time;
	char *nick;
} COMPLETION_REC;

#define replace_find(replace) \
	iconfig_list_find("replaces", "text", replace, "replace")

#define completion_find(completion) \
	iconfig_list_find("completions", "short", completion, "long")

static gint comptag;
static GList *complist;

static COMPLETION_REC *nick_completion_find(GSList *list, gchar *nick)
{
    GSList *tmp;

    for (tmp = list; tmp != NULL; tmp = tmp->next)
    {
        COMPLETION_REC *rec = tmp->data;

        if (g_strcasecmp(rec->nick, nick) == 0) return rec;
    }

    return NULL;
}

static void completion_destroy(GSList **list, COMPLETION_REC *rec)
{
    *list = g_slist_remove(*list, rec);

    g_free(rec->nick);
    g_free(rec);
}

static COMPLETION_REC *nick_completion_create(GSList **list, time_t time, gchar *nick)
{
    COMPLETION_REC *rec;

    rec = nick_completion_find(*list, nick);
    if (rec != NULL)
    {
        /* remove the old one */
        completion_destroy(list, rec);
    }

    rec = g_new(COMPLETION_REC, 1);
    *list = g_slist_prepend(*list, rec);

    rec->time = time;
    rec->nick = g_strdup(nick);
    return rec;
}

static void completion_checklist(GSList **list, gint timeout, time_t t)
{
    GSList *tmp, *next;

    for (tmp = *list; tmp != NULL; tmp = next)
    {
        COMPLETION_REC *rec = tmp->data;

        next = tmp->next;
        if (t-rec->time > timeout)
            completion_destroy(list, rec);
    }
}

static gint completion_timeout(void)
{
    GSList *tmp, *link;
    time_t t;
    gint len;

    t = time(NULL);
    for (tmp = servers; tmp != NULL; tmp = tmp->next)
    {
        IRC_SERVER_REC *rec = tmp->data;

        len = g_slist_length(rec->lastmsgs);
        if (len > 0 && len >= settings_get_int("completion_keep_privates"))
        {
            link = g_slist_last(rec->lastmsgs);
            g_free(link->data);
            rec->lastmsgs = g_slist_remove_link(rec->lastmsgs, link);
            g_slist_free_1(link);
        }
    }

    for (tmp = channels; tmp != NULL; tmp = tmp->next)
    {
        CHANNEL_REC *rec = tmp->data;

        completion_checklist(&rec->lastownmsgs, settings_get_int("completion_keep_ownpublics"), t);
        completion_checklist(&rec->lastmsgs, settings_get_int("completion_keep_publics"), t);
    }

    return 1;
}

static void add_private_msg(IRC_SERVER_REC *server, gchar *nick)
{
    GSList *link;

    link = gslist_find_icase_string(server->lastmsgs, nick);
    if (link != NULL)
    {
	g_free(link->data);
	server->lastmsgs = g_slist_remove_link(server->lastmsgs, link);
	g_slist_free_1(link);
    }
    server->lastmsgs = g_slist_prepend(server->lastmsgs, g_strdup(nick));
}

static void event_privmsg(gchar *data, IRC_SERVER_REC *server, gchar *nick)
{
    gchar *params, *target, *msg;
    GSList **list;

    g_return_if_fail(server != NULL);
    if (nick == NULL) return; /* from server */

    params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

    if (*msg == 1)
    {
        /* ignore ctcp messages */
        g_free(params);
        return;
    }

    if (ischannel(*target))
    {
        /* channel message */
        CHANNEL_REC *channel;

        channel = channel_find(server, target);
        if (channel == NULL)
        {
            g_free(params);
            return;
        }

        list = irc_nick_match(server->nick, msg) ?
            &channel->lastownmsgs :
            &channel->lastmsgs;
        nick_completion_create(list, time(NULL), nick);
    }
    else
    {
	/* private message */
        add_private_msg(server, nick);
    }

    g_free(params);
}

static void cmd_msg(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *target, *msg;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);
    if (*target != '\0' && *msg != '\0')
    {
	if (!ischannel(*target) && *target != '=' && server != NULL)
	    add_private_msg(server, target);
    }

    g_free(params);
}

static void complete_list(GList **outlist, GSList *list, gchar *nick)
{
    GSList *tmp;
    gint len;

    len = strlen(nick);
    for (tmp = list; tmp != NULL; tmp = tmp->next)
    {
        COMPLETION_REC *rec = tmp->data;

        if (g_strncasecmp(rec->nick, nick, len) == 0 &&
            glist_find_icase_string(*outlist, rec->nick) == NULL)
            *outlist = g_list_append(*outlist, g_strdup(rec->nick));
    }
}

static GList *completion_getlist(CHANNEL_REC *channel, gchar *nick)
{
    GSList *nicks, *tmp;
    GList *list;
    gint len;

    g_return_val_if_fail(channel != NULL, NULL);
    g_return_val_if_fail(nick != NULL, NULL);
    if (*nick == '\0') return NULL;

    list = NULL;
    complete_list(&list, channel->lastownmsgs, nick);
    complete_list(&list, channel->lastmsgs, nick);

    len = strlen(nick);
    nicks = nicklist_getnicks(channel);
    for (tmp = nicks; tmp != NULL; tmp = tmp->next)
    {
        NICK_REC *rec = tmp->data;

        if (g_strncasecmp(rec->nick, nick, len) == 0 &&
            glist_find_icase_string(list, rec->nick) == NULL &&
            g_strcasecmp(rec->nick, channel->server->nick) != 0)
            list = g_list_append(list, g_strdup(rec->nick));
    }
    g_slist_free(nicks);

    return list;
}

static GList *completion_getmsglist(IRC_SERVER_REC *server, gchar *nick)
{
    GSList *tmp;
    GList *list;
    gint len;

    list = NULL; len = strlen(nick);
    for (tmp = server->lastmsgs; tmp != NULL; tmp = tmp->next)
    {
        if (len == 0 || g_strncasecmp(tmp->data, nick, len) == 0)
            list = g_list_append(list, g_strdup(tmp->data));
    }

    return list;
}

static void event_text(gchar *line, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
    CHANNEL_REC *channel;
    GList *comp;
    gchar *str, *ptr;

    g_return_if_fail(line != NULL);

    if (!irc_item_check(item))
	    return;

    line = g_strdup(line);

    /* check for nick completion */
    if (settings_get_bool("completion_disable_auto") || *settings_get_str("completion_char") == '\0')
    {
	ptr = NULL;
	comp = NULL;
    }
    else
    {
	ptr = strchr(line, *settings_get_str("completion_char"));
	if (ptr != NULL) *ptr++ = '\0';

	channel = irc_item_channel(item);

	comp = ptr == NULL || channel == NULL ||
	    nicklist_find(channel, line) != NULL ? NULL :
	    completion_getlist(channel, line);
    }

    /* message to channel */
    if (ptr == NULL)
        str = g_strdup_printf("%s %s", item->name, line);
    else
    {
        str = g_strdup_printf("%s %s%s%s", item->name,
                              comp != NULL ? (gchar *) comp->data : line,
                              settings_get_str("completion_char"), ptr);
    }
    signal_emit("command msg", 3, str, server, item);

    g_free(str);
    g_free(line);

    if (comp != NULL)
    {
        g_list_foreach(comp, (GFunc) g_free, NULL);
        g_list_free(comp);
    }

    signal_stop();
}

static GList *completion_joinlist(GList *list1, GList *list2)
{
    while (list2 != NULL)
    {
	if (!glist_find_icase_string(list1, list2->data))
	    list1 = g_list_append(list1, list2->data);
	else
	    g_free(list2->data);

	list2 = list2->next;
    }
    g_list_free(list2);
    return list1;
}

char *auto_completion(const char *line, int *pos)
{
    const char *replace;
    gchar *word, *ret;
    gint spos, epos, n, wordpos;
    GString *result;

    g_return_val_if_fail(line != NULL, NULL);
    g_return_val_if_fail(pos != NULL, NULL);

    spos = *pos;

    /* get the word we are completing.. */
    while (spos > 0 && isspace((gint) line[spos-1])) spos--;
    epos = spos;
    while (spos > 0 && !isspace((gint) line[spos-1])) spos--;
    while (line[epos] != '\0' && !isspace((gint) line[epos])) epos++;

    word = g_strdup(line+spos);
    word[epos-spos] = '\0';

    /* word position in line */
    wordpos = 0;
    for (n = 0; n < spos; )
    {
        while (n < spos && isspace((gint) line[n])) n++;
        while (n < spos && !isspace((gint) line[n])) n++;
        if (n < spos) wordpos++;
    }

    result = g_string_new(line);
    g_string_erase(result, spos, epos-spos);

    /* check for words in autocompletion list */
    replace = replace_find(word); g_free(word);
    if (replace != NULL)
    {
        *pos = spos+strlen(replace);

        g_string_insert(result, spos, replace);
        ret = result->str;
        g_string_free(result, FALSE);
        return ret;
    }

    g_string_free(result, TRUE);
    return NULL;
}

#define issplit(a) ((a) == ',' || (a) == ' ')

char *completion_line(WINDOW_REC *window, const char *line, int *pos)
{
    static gboolean msgcomp = FALSE;
    const char *completion;
    CHANNEL_REC *channel;
    SERVER_REC *server;
    gchar *word, *ret;
    gint spos, epos, len, n, wordpos;
    gboolean msgcompletion;
    GString *result;

    g_return_val_if_fail(window != NULL, NULL);
    g_return_val_if_fail(line != NULL, NULL);
    g_return_val_if_fail(pos != NULL, NULL);

    spos = *pos;

    /* get the word we are completing.. */
    while (spos > 0 && issplit((gint) line[spos-1])) spos--;
    epos = spos;
    if (line[epos] == ',') epos++;
    while (spos > 0 && !issplit((gint) line[spos-1])) spos--;
    while (line[epos] != '\0' && !issplit((gint) line[epos])) epos++;

    word = g_strdup(line+spos);
    word[epos-spos] = '\0';

    /* word position in line */
    wordpos = 0;
    for (n = 0; n < spos; )
    {
        while (n < spos && issplit((gint) line[n])) n++;
        while (n < spos && !issplit((gint) line[n])) n++;
        if (n < spos) wordpos++;
    }

    server = window->active == NULL ? window->active_server : window->active->server;
    msgcompletion = server != NULL &&
        (*line == '\0' || ((wordpos == 0 || wordpos == 1) && g_strncasecmp(line, "/msg ", 5) == 0));

    if (msgcompletion && wordpos == 0 && issplit((gint) line[epos]))
    {
        /* /msg <tab> */
        *word = '\0'; epos++; spos = epos; wordpos = 1;
    }

    /* are we completing the same nick as last time?
       if not, forget the old completion.. */
    len = strlen(word)-(msgcomp == FALSE && word[strlen(word)-1] == *settings_get_str("completion_char"));
    if (complist != NULL && (strlen(complist->data) != len || g_strncasecmp(complist->data, word, len) != 0))
    {
        g_list_foreach(complist, (GFunc) g_free, NULL);
        g_list_free(complist);

        complist = NULL;
    }

    result = g_string_new(line);
    g_string_erase(result, spos, epos-spos);

    /* check for words in completion list */
    completion = completion_find(word);
    if (completion != NULL)
    {
        g_free(word);
        *pos = spos+strlen(completion);

        g_string_insert(result, spos, completion);
        ret = result->str;
        g_string_free(result, FALSE);
        return ret;
    }

    channel = irc_item_channel(window->active);
    if (complist == NULL && !msgcompletion && channel == NULL)
    {
        /* don't try nick completion */
        g_free(word);
        g_string_free(result, TRUE);
        return NULL;
    }

    if (complist == NULL)
    {
        /* start new nick completion */
	    complist = channel == NULL ? NULL : completion_getlist(channel, word);

        if (!msgcompletion)
        {
            /* nick completion in channel */
            msgcomp = FALSE;
	}
	else
	{
	    GList *tmpcomp;

            /* /msg completion */
            msgcomp = TRUE;

	    /* first get the list of msg nicks and then nicks from current
	       channel. */
	    tmpcomp = complist;
	    complist = completion_getmsglist((IRC_SERVER_REC *) server, word);
	    complist = completion_joinlist(complist, tmpcomp);
            if (*line == '\0')
            {
                /* completion in empty line -> /msg <nick> */
                g_free(word);
                g_string_free(result, TRUE);

                if (complist == NULL)
                    ret = g_strdup("/msg ");
                else
                    ret = g_strdup_printf("/msg %s ", (gchar *) complist->data);
                *pos = strlen(ret);
                return ret;
            }
        }

        if (complist == NULL)
        {
            g_free(word);
            g_string_free(result, TRUE);
            return NULL;
        }
    }
    else
    {
        /* continue the last completion */
        complist = complist->next == NULL ? g_list_first(complist) : complist->next;
    }
    g_free(word);

    /* insert the nick.. */
    g_string_insert(result, spos, complist->data);
    *pos = spos+strlen(complist->data);

    if (!msgcomp && wordpos == 0)
    {
        /* insert completion character */
        g_string_insert(result, *pos, settings_get_str("completion_char"));
        *pos += strlen(settings_get_str("completion_char"));
    }
    if (msgcomp || wordpos == 0)
    {
        if (!issplit((gint) result->str[*pos]))
        {
            /* insert space */
            g_string_insert(result, *pos, " ");
        }
        (*pos)++;
    }

    ret = result->str;
    g_string_free(result, FALSE);
    return ret;
}

static void completion_deinit_server(IRC_SERVER_REC *server)
{
    g_return_if_fail(server != NULL);

    g_slist_foreach(server->lastmsgs, (GFunc) g_free, NULL);
    g_slist_free(server->lastmsgs);
}

static void completion_deinit_channel(CHANNEL_REC *channel)
{
    g_return_if_fail(channel != NULL);

    while (channel->lastmsgs != NULL)
        completion_destroy(&channel->lastmsgs, channel->lastmsgs->data);
    while (channel->lastownmsgs != NULL)
        completion_destroy(&channel->lastownmsgs, channel->lastownmsgs->data);
    g_slist_free(channel->lastmsgs);
    g_slist_free(channel->lastownmsgs);
}

void completion_init(void)
{
	settings_add_str("completion", "completion_char", ":");
	settings_add_bool("completion", "completion_disable_auto", FALSE);
	settings_add_int("completion", "completion_keep_publics", 180);
	settings_add_int("completion", "completion_keep_ownpublics", 360);
	settings_add_int("completion", "completion_keep_privates", 10);

	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("send text", (SIGNAL_FUNC) event_text);
	signal_add("server disconnected", (SIGNAL_FUNC) completion_deinit_server);
	signal_add("channel destroyed", (SIGNAL_FUNC) completion_deinit_channel);
	command_bind("msg", NULL, (SIGNAL_FUNC) cmd_msg);

	comptag = g_timeout_add(1000, (GSourceFunc) completion_timeout, NULL);
	complist = NULL;
}

void completion_deinit(void)
{
	g_list_foreach(complist, (GFunc) g_free, NULL);
	g_list_free(complist);

	g_source_remove(comptag);

	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("send text", (SIGNAL_FUNC) event_text);
	signal_remove("server disconnected", (SIGNAL_FUNC) completion_deinit_server);
	signal_remove("channel destroyed", (SIGNAL_FUNC) completion_deinit_channel);
	command_unbind("msg", (SIGNAL_FUNC) cmd_msg);
}
