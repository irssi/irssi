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
#include "channels-setup.h"
#include "nicklist.h"

#include "completion.h"
#include "window-items.h"

static int complete_tag;

typedef struct {
	time_t time;
	char *nick;
} NICK_COMPLETION_REC;

GList *completion_get_channels(IRC_SERVER_REC *server, const char *word)
{
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);
	g_return_val_if_fail(*word != '\0', NULL);

	len = strlen(word);
	list = NULL;

	/* first get the joined channels */
	tmp = server == NULL ? NULL : server->channels;
	for (; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (g_strncasecmp(rec->name, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->name));
	}

	/* get channels from setup */
	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		SETUP_CHANNEL_REC *rec = tmp->data;

		if (g_strncasecmp(rec->name, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->name));

	}

	return list;
}

static void nick_completion_destroy(GSList **list, NICK_COMPLETION_REC *rec)
{
	*list = g_slist_remove(*list, rec);

	g_free(rec->nick);
	g_free(rec);
}

static void nick_completion_remove_old(GSList **list, int timeout, time_t now)
{
	GSList *tmp, *next;

	for (tmp = *list; tmp != NULL; tmp = next) {
		NICK_COMPLETION_REC *rec = tmp->data;

		next = tmp->next;
		if (now-rec->time > timeout)
			nick_completion_destroy(list, rec);
	}
}

static int nick_completion_timeout(void)
{
	GSList *tmp, *link;
	time_t now;
	int len;

	now = time(NULL);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		len = g_slist_length(rec->lastmsgs);
		if (len > 0 && len >= settings_get_int("completion_keep_privates")) {
			link = g_slist_last(rec->lastmsgs);
			g_free(link->data);
			rec->lastmsgs = g_slist_remove(rec->lastmsgs, link->data);
		}
	}

	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		nick_completion_remove_old(&rec->lastownmsgs, settings_get_int("completion_keep_ownpublics"), now);
		nick_completion_remove_old(&rec->lastmsgs, settings_get_int("completion_keep_publics"), now);
	}

	return 1;
}

static NICK_COMPLETION_REC *nick_completion_find(GSList *list, const char *nick)
{
	GSList *tmp;

	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		NICK_COMPLETION_REC *rec = tmp->data;

		if (g_strcasecmp(rec->nick, nick) == 0)
			return rec;
	}

	return NULL;
}

static NICK_COMPLETION_REC *nick_completion_create(GSList **list, time_t time, const char *nick)
{
	NICK_COMPLETION_REC *rec;

	rec = nick_completion_find(*list, nick);
	if (rec != NULL) {
		/* remove the old one */
		nick_completion_destroy(list, rec);
	}

	rec = g_new(NICK_COMPLETION_REC, 1);
	*list = g_slist_prepend(*list, rec);

	rec->time = time;
	rec->nick = g_strdup(nick);
	return rec;
}

static void add_private_msg(IRC_SERVER_REC *server, const char *nick)
{
	GSList *link;

	link = gslist_find_icase_string(server->lastmsgs, nick);
	if (link != NULL) {
		g_free(link->data);
		server->lastmsgs = g_slist_remove(server->lastmsgs, link->data);
	}
	server->lastmsgs = g_slist_prepend(server->lastmsgs, g_strdup(nick));
}

static void event_privmsg(const char *data, IRC_SERVER_REC *server, const char *nick)
{
	char *params, *target, *msg;
	GSList **list;

	g_return_if_fail(server != NULL);
	if (nick == NULL) return; /* from server */

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, &target, &msg);

	if (ischannel(*target)) {
		/* channel message */
		CHANNEL_REC *channel;

		channel = channel_find(server, target);
		if (channel == NULL) {
			g_free(params);
			return;
		}

		list = irc_nick_match(server->nick, msg) ?
			&channel->lastownmsgs :
			&channel->lastmsgs;
		nick_completion_create(list, time(NULL), nick);
	} else {
		/* private message */
		add_private_msg(server, nick);
	}

	g_free(params);
}

static void cmd_msg(const char *data, IRC_SERVER_REC *server)
{
	char *target, *msg;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &target, &msg))
		return;
	if (*target != '\0' && *msg != '\0') {
		if (!ischannel(*target) && *target != '=' && server != NULL)
			add_private_msg(server, target);
	}

	cmd_params_free(free_arg);
}

static void sig_nick_removed(CHANNEL_REC *channel, NICK_REC *nick)
{
	NICK_COMPLETION_REC *rec;

	rec = nick_completion_find(channel->lastownmsgs, nick->nick);
	if (rec != NULL) nick_completion_destroy(&channel->lastownmsgs, rec);

	rec = nick_completion_find(channel->lastmsgs, nick->nick);
	if (rec != NULL) nick_completion_destroy(&channel->lastmsgs, rec);
}

static void sig_nick_changed(CHANNEL_REC *channel, NICK_REC *nick, const char *oldnick)
{
	NICK_COMPLETION_REC *rec;

	rec = nick_completion_find(channel->lastownmsgs, oldnick);
	if (rec != NULL) {
		g_free(rec->nick);
		rec->nick = g_strdup(nick->nick);
	}

	rec = nick_completion_find(channel->lastmsgs, oldnick);
	if (rec != NULL) {
		g_free(rec->nick);
		rec->nick = g_strdup(nick->nick);
	}
}

static GList *completion_msg(IRC_SERVER_REC *server, const char *nick, const char *prefix)
{
	GSList *tmp;
	GList *list;
	int len;

	list = NULL; len = strlen(nick);
	for (tmp = server->lastmsgs; tmp != NULL; tmp = tmp->next) {
		if (len == 0 || g_strncasecmp(tmp->data, nick, len) == 0) {
			if (prefix == NULL || *prefix == '\0')
				list = g_list_append(list, g_strdup(tmp->data));
			else
				list = g_list_append(list, g_strconcat(prefix, " ", tmp->data, NULL));
		}
	}

	return list;
}

static void complete_from_nicklist(GList **outlist, GSList *list,
				   const char *nick, const char *prefix)
{
	GSList *tmp;
	int len;

	len = strlen(nick);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		NICK_COMPLETION_REC *rec = tmp->data;

		if (g_strncasecmp(rec->nick, nick, len) == 0 &&
		    glist_find_icase_string(*outlist, rec->nick) == NULL) {
			if (prefix == NULL || *prefix == '\0')
				*outlist = g_list_append(*outlist, g_strdup(rec->nick));
			else
				*outlist = g_list_append(*outlist, g_strconcat(rec->nick, prefix, NULL));
		}
	}
}

static GList *completion_channel_nicks(CHANNEL_REC *channel, const char *nick, const char *prefix)
{
	GSList *nicks, *tmp;
	GList *list;
	int len;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	if (*nick == '\0') return NULL;

	/* put first the nicks who have recently said something [to you] */
	list = NULL;
	complete_from_nicklist(&list, channel->lastownmsgs, nick, prefix);
	complete_from_nicklist(&list, channel->lastmsgs, nick, prefix);

	/* and add the rest of the nicks too */
	len = strlen(nick);
	nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		if (g_strncasecmp(rec->nick, nick, len) == 0 &&
		    glist_find_icase_string(list, rec->nick) == NULL &&
		    g_strcasecmp(rec->nick, channel->server->nick) != 0) {
			if (prefix == NULL || *prefix == '\0')
				list = g_list_append(list, g_strdup(rec->nick));
			else
				list = g_list_append(list, g_strconcat(rec->nick, prefix, NULL));
		}
	}
	g_slist_free(nicks);

	return list;
}

static GList *completion_joinlist(GList *list1, GList *list2)
{
	GList *old;

	old = list2;
	while (list2 != NULL) {
		if (!glist_find_icase_string(list1, list2->data))
			list1 = g_list_append(list1, list2->data);
		else
			g_free(list2->data);

		list2 = list2->next;
	}

	g_list_free(old);
	return list1;
}

static void sig_complete_word(GList **list, WINDOW_REC *window,
			      const char *word, const char *linestart)
{
	IRC_SERVER_REC *server;
	CHANNEL_REC *channel;
	GList *tmplist;
	const char *cmdchars, *nickprefix;
	char *prefix;

	g_return_if_fail(list != NULL);
	g_return_if_fail(window != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(linestart != NULL);

	if (ischannel(*word)) {
		/* probably completing a channel name */
		*list = completion_get_channels((IRC_SERVER_REC *) window->active_server, word);
                return;
	}

	server = window->active_server;
	if (server == NULL || !server->connected)
		return;

	channel = irc_item_channel(window->active);

	/* check for /MSG completion */
	cmdchars = settings_get_str("cmdchars");
	if (*word == '\0' || (*linestart == '\0' && strchr(cmdchars, *word) != NULL &&
			      g_strcasecmp(word+1, "msg") == 0)) {
		/* pressed TAB at the start of line - add /MSG
		   ... or ... trying to complete /MSG command */
                prefix = g_strdup_printf("%cmsg", *cmdchars);
		*list = completion_msg(server, "", prefix);
		if (*list == NULL) *list = g_list_append(*list, g_strdup(prefix));
		g_free(prefix);

		signal_stop();
		return;
	}

	if (strchr(cmdchars, *linestart) != NULL &&
	    g_strcasecmp(linestart+1, "msg") == 0) {
                /* completing /MSG nick */
		*list = completion_msg(server, word, NULL);
	}

	/* nick completion .. we could also be completing a nick after /MSG
	   from nicks in channel */
	if (channel == NULL)
		return;

	nickprefix = *linestart != '\0' ? NULL :
		settings_get_str("completion_char");

	tmplist = completion_channel_nicks(channel, word, nickprefix);
	*list = completion_joinlist(*list, tmplist);

	if (*list != NULL) signal_stop();
}

/* expand \n, \t and \\ - FIXME: this doesn't work right */
static char *expand_escapes(const char *line, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	char *ptr, *ret;

	ret = ptr = g_malloc(strlen(line)+1);
	while (*line != '\0') {
		if (*line != '\\')
			*ptr++ = *line;
		else {
			line++;
			if (*line == '\0') {
                                *ptr++ = '\\';
				break;
			}

			switch (*line) {
			case 'n':
				/* newline .. we need to send another "send text" event to handle it (or actually the text before the newline..) */
				*ptr = '\0';
                                signal_emit("send text", 3, ret, server, item);
				ptr = ret;
				break;
			case 't':
				*ptr++ = '\t';
				break;
			case '\\':
                                *ptr++ = '\\';
				break;
			default:
				*ptr++ = '\\';
				*ptr++ = *line;
				break;
			}
		}
		line++;
	}

	*ptr = '\0';
	return ret;
}

static void event_text(gchar *line, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
    CHANNEL_REC *channel;
    GList *comp;
    gchar *str, *ptr;

    g_return_if_fail(line != NULL);

    if (!irc_item_check(item))
	    return;

    /* FIXME: this really should go to fe-common/core. */
    line = settings_get_bool("expand_escapes") ?
	    expand_escapes(line, server, item) : g_strdup(line);

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
	    completion_channel_nicks(channel, line, NULL);
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
		nick_completion_destroy(&channel->lastmsgs, channel->lastmsgs->data);
	while (channel->lastownmsgs != NULL)
		nick_completion_destroy(&channel->lastownmsgs, channel->lastownmsgs->data);

	g_slist_free(channel->lastmsgs);
	g_slist_free(channel->lastownmsgs);
}

void irc_completion_init(void)
{
	settings_add_str("completion", "completion_char", ":");
	settings_add_bool("completion", "completion_disable_auto", FALSE);
	settings_add_int("completion", "completion_keep_publics", 180);
	settings_add_int("completion", "completion_keep_ownpublics", 360);
	settings_add_int("completion", "completion_keep_privates", 10);
	settings_add_bool("completion", "expand_escapes", FALSE);

	complete_tag = g_timeout_add(1000, (GSourceFunc) nick_completion_timeout, NULL);

	signal_add("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_add("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_add("command msg", (SIGNAL_FUNC) cmd_msg);
	signal_add("nicklist remove", (SIGNAL_FUNC) sig_nick_removed);
	signal_add("nicklist changed", (SIGNAL_FUNC) sig_nick_changed);
	signal_add("send text", (SIGNAL_FUNC) event_text);
	signal_add("server disconnected", (SIGNAL_FUNC) completion_deinit_server);
	signal_add("channel destroyed", (SIGNAL_FUNC) completion_deinit_channel);
}

void irc_completion_deinit(void)
{
	g_source_remove(complete_tag);

	signal_remove("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_remove("event privmsg", (SIGNAL_FUNC) event_privmsg);
	signal_remove("command msg", (SIGNAL_FUNC) cmd_msg);
	signal_remove("nicklist remove", (SIGNAL_FUNC) sig_nick_removed);
	signal_remove("nicklist changed", (SIGNAL_FUNC) sig_nick_changed);
	signal_remove("send text", (SIGNAL_FUNC) event_text);
	signal_remove("server disconnected", (SIGNAL_FUNC) completion_deinit_server);
	signal_remove("channel destroyed", (SIGNAL_FUNC) completion_deinit_channel);
}
