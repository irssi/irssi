/*
 chat-completion.c : irssi

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

#include "servers.h"
#include "chatnets.h"
#include "servers-setup.h"
#include "channels.h"
#include "channels-setup.h"
#include "queries.h"
#include "nicklist.h"

#include "completion.h"
#include "window-items.h"

static int complete_tag;

#define SERVER_LAST_MSG_ADD(server, nick) \
	last_msg_add(&server->lastmsgs, nick)
#define SERVER_LAST_MSG_DESTROY(server, nick) \
	last_msg_destroy(&server->lastmsgs, nick)

static LAST_MSG_REC *last_msg_find(GSList *list, const char *nick)
{
	while (list != NULL) {
		LAST_MSG_REC *rec = list->data;

		if (g_strcasecmp(rec->nick, nick) == 0)
			return rec;
		list = list->next;
	}

	return NULL;
}

static void last_msg_add(GSList **list, const char *nick)
{
	LAST_MSG_REC *rec;

	rec = last_msg_find(*list, nick);
	if (rec != NULL) {
		/* msg already exists, update it */
                *list = g_slist_remove(*list, rec);
	} else {
		rec = g_new(LAST_MSG_REC, 1);
		rec->nick = g_strdup(nick);
	}
	rec->time = time(NULL);

	*list = g_slist_prepend(*list, rec);
}

static void last_msg_destroy(GSList **list, LAST_MSG_REC *rec)
{
	*list = g_slist_remove(*list, rec);

	g_free(rec->nick);
	g_free(rec);
}

static void last_msgs_remove_old(GSList **list, int timeout, time_t now)
{
	GSList *tmp, *next;

	for (tmp = *list; tmp != NULL; tmp = next) {
		LAST_MSG_REC *rec = tmp->data;

		next = tmp->next;
		if (now-rec->time > timeout)
			last_msg_destroy(list, rec);
	}
}

static int last_msg_cmp(LAST_MSG_REC *m1, LAST_MSG_REC *m2)
{
	return m1->time < m2->time ? 1 : -1;
}

static int nick_completion_timeout(void)
{
	GSList *tmp;
	time_t now;
	int len, keep_private_count;
	int keep_msgs_time, keep_msgs_count, keep_ownmsgs_time;

	keep_private_count = settings_get_int("completion_keep_privates");

	now = time(NULL);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		len = g_slist_length(server->lastmsgs);
		if (len > 0 && len >= keep_private_count) {
                        /* remove the oldest msg nick. */
			GSList *link = g_slist_last(server->lastmsgs);
			SERVER_LAST_MSG_DESTROY(server, link->data);
		}
	}

	keep_ownmsgs_time = settings_get_int("completion_keep_ownpublics");
	keep_msgs_time = settings_get_int("completion_keep_publics");
	keep_msgs_count = settings_get_int("completion_keep_publics_count");

	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;

		last_msgs_remove_old(&channel->lastmsgs, keep_msgs_time, now);

		if (keep_msgs_count == 0 ||
		    (int)g_slist_length(channel->lastownmsgs) > keep_msgs_count) {
			last_msgs_remove_old(&channel->lastownmsgs,
					     keep_ownmsgs_time, now);
		}
	}

	return 1;
}

static void sig_message_public(SERVER_REC *server, const char *msg,
			       const char *nick, const char *address,
			       const char *target)
{
	CHANNEL_REC *channel;
	GSList **list;

	channel = channel_find(server, target);
	if (channel != NULL) {
		list = nick_match_msg(server, msg, server->nick) ?
			&channel->lastownmsgs :
			&channel->lastmsgs;
                last_msg_add(list, nick);
	}
}

static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *address)
{
	SERVER_LAST_MSG_ADD(server, nick);
}

static void cmd_msg(const char *data, SERVER_REC *server)
{
	GHashTable *optlist;
	char *target, *msg;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			    "msg", &optlist, &target, &msg))
		return;
	server = cmd_options_get_server("msg", optlist, server);

	if (*target != '\0' && *msg != '\0' && *target != '=' &&
	    server != NULL && !server->ischannel(*target))
		SERVER_LAST_MSG_ADD(server, target);

	cmd_params_free(free_arg);
}

static void sig_nick_removed(CHANNEL_REC *channel, NICK_REC *nick)
{
	LAST_MSG_REC *rec;

	rec = last_msg_find(channel->lastownmsgs, nick->nick);
	if (rec != NULL) last_msg_destroy(&channel->lastownmsgs, rec);

	rec = last_msg_find(channel->lastmsgs, nick->nick);
	if (rec != NULL) last_msg_destroy(&channel->lastmsgs, rec);
}

static void sig_nick_changed(CHANNEL_REC *channel, NICK_REC *nick,
			     const char *oldnick)
{
	LAST_MSG_REC *rec;

	rec = last_msg_find(channel->lastownmsgs, oldnick);
	if (rec != NULL) {
		g_free(rec->nick);
		rec->nick = g_strdup(nick->nick);
	}

	rec = last_msg_find(channel->lastmsgs, oldnick);
	if (rec != NULL) {
		g_free(rec->nick);
		rec->nick = g_strdup(nick->nick);
	}
}

/* Complete /MSG from specified server */
static void completion_msg_server(GSList **list, SERVER_REC *server,
				  const char *nick, const char *prefix)
{
	LAST_MSG_REC *msg;
	GSList *tmp;
	int len;

	g_return_if_fail(nick != NULL);

	len = strlen(nick);
	for (tmp = server->lastmsgs; tmp != NULL; tmp = tmp->next) {
		LAST_MSG_REC *rec = tmp->data;

		if (len != 0 && g_strncasecmp(rec->nick, nick, len) != 0)
			continue;

		msg = g_new(LAST_MSG_REC, 1);
		msg->time = rec->time;
		msg->nick = prefix == NULL || *prefix == '\0' ?
			g_strdup(rec->nick) :
			g_strconcat(prefix, " ", rec->nick, NULL);
		*list = g_slist_insert_sorted(*list, msg,
					      (GCompareFunc) last_msg_cmp);
	}
}

/* convert list of LAST_MSG_REC's to list of char* nicks. */
static GList *convert_msglist(GSList *msglist)
{
	GList *list;

	list = NULL;
	while (msglist != NULL) {
		LAST_MSG_REC *rec = msglist->data;

                list = g_list_append(list, rec->nick);
		msglist = g_slist_remove(msglist, rec);
		g_free(rec);
	}

	return list;
}

/* Complete /MSG - if `find_server' is NULL, complete nicks from all servers */
static GList *completion_msg(SERVER_REC *win_server,
			     SERVER_REC *find_server,
			     const char *nick, const char *prefix)
{
	GSList *tmp, *list;
	char *newprefix;

	g_return_val_if_fail(nick != NULL, NULL);
	if (servers == NULL) return NULL;

	list = NULL;
	if (find_server != NULL) {
		completion_msg_server(&list, find_server, nick, prefix);
		return convert_msglist(list);
	}

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		if (rec == win_server)
			newprefix = g_strdup(prefix);
		else {
			newprefix = prefix == NULL ?
				g_strdup_printf("-%s", rec->tag) :
				g_strdup_printf("%s -%s", prefix, rec->tag);
		}

		completion_msg_server(&list, rec, nick, newprefix);
		g_free_not_null(newprefix);
	}

	return convert_msglist(list);
}

static void complete_from_nicklist(GList **outlist, GSList *list,
				   const char *nick, const char *prefix)
{
	GSList *tmp;
	char *str;
	int len, lowercase;

	lowercase = settings_get_bool("completion_nicks_lowercase");

	len = strlen(nick);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		LAST_MSG_REC *rec = tmp->data;

		if (g_strncasecmp(rec->nick, nick, len) == 0 &&
		    glist_find_icase_string(*outlist, rec->nick) == NULL) {
			str = g_strconcat(rec->nick, prefix, NULL);
			if (lowercase) g_strdown(str);
			*outlist = g_list_append(*outlist, str);
		}
	}
}

static GList *completion_channel_nicks(CHANNEL_REC *channel, const char *nick,
				       const char *prefix)
{
	GSList *nicks, *tmp;
	GList *list;
	char *str;
	int lowercase, len;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	if (*nick == '\0') return NULL;

	lowercase = settings_get_bool("completion_nicks_lowercase");

	if (prefix != NULL && *prefix == '\0')
		prefix = NULL;

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
			str = g_strconcat(rec->nick, prefix, NULL);
			if (lowercase) g_strdown(str);
			list = g_list_append(list, str);
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

GList *completion_get_channels(SERVER_REC *server, const char *word)
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
		CHANNEL_SETUP_REC *rec = tmp->data;

		if (g_strncasecmp(rec->name, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->name));

	}

	return list;
}

static void complete_window_nicks(GList **list, WINDOW_REC *window,
                                  const char *word, const char *linestart)
{
        CHANNEL_REC *channel;
        GList *tmplist;
        GSList *tmp;
        const char *nickprefix;

        nickprefix = *linestart != '\0' ? NULL :
                settings_get_str("completion_char");

        channel = CHANNEL(window->active);

        /* first the active channel */
        if (channel != NULL) {
                tmplist = completion_channel_nicks(channel, word, nickprefix);
                *list = completion_joinlist(*list, tmplist);
        }

        if (nickprefix != NULL) {
                /* completing nick at the start of line - probably answering
                   to some other nick, don't even try to complete from
                   non-active channels */
                return;
        }

        /* then the rest */
        for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
                channel = CHANNEL(tmp->data);
                if (channel != NULL && tmp->data != window->active) {
                        tmplist = completion_channel_nicks(channel, word,
                                                           nickprefix);
                        *list = completion_joinlist(*list, tmplist);
                }
        }
}

static void sig_complete_word(GList **list, WINDOW_REC *window,
			      const char *word, const char *linestart)
{
	SERVER_REC *server;
	CHANNEL_REC *channel;
	QUERY_REC *query;
	const char *cmdchars;
	char *prefix;

	g_return_if_fail(list != NULL);
	g_return_if_fail(window != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(linestart != NULL);

	server = window->active_server;
	if (server == NULL && servers != NULL)
		server = servers->data;

	if (server != NULL && server->ischannel(*word)) {
		/* probably completing a channel name */
		*list = completion_get_channels(window->active_server, word);
                return;
	}

	server = window->active_server;
	if (server == NULL || !server->connected)
		return;

	cmdchars = settings_get_str("cmdchars");
	if (*linestart == '\0' && *word == '\0') {
		/* pressed TAB at the start of line - add /MSG */
                prefix = g_strdup_printf("%cmsg", *cmdchars);
		*list = completion_msg(server, NULL, "", prefix);
		if (*list == NULL)
			*list = g_list_append(*list, g_strdup(prefix));
		g_free(prefix);

		signal_stop();
		return;
	}

	channel = CHANNEL(window->active);
	query = QUERY(window->active);
	if (channel == NULL && query != NULL) {
		/* completion in query */
                *list = g_list_append(*list, g_strdup(query->name));
	} else if (channel != NULL) {
		/* nick completion .. we could also be completing a nick
		   after /MSG from nicks in channel */
                complete_window_nicks(list, window, word, linestart);
	}

	if (*list != NULL) signal_stop();
}

static SERVER_REC *line_get_server(const char *line)
{
	SERVER_REC *server;
	char *tag, *ptr;

	g_return_val_if_fail(line != NULL, NULL);
	if (*line != '-') return NULL;

	/* -option found - should be server tag */
	tag = g_strdup(line+1);
	ptr = strchr(tag, ' ');
	if (ptr != NULL) *ptr = '\0';

	server = server_find_tag(tag);

	g_free(tag);
	return server;
}

static void sig_complete_msg(GList **list, WINDOW_REC *window,
			     const char *word, const char *line,
			     int *want_space)
{
	SERVER_REC *server, *msgserver;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	server = window->active_server;
	if (server == NULL || !server->connected)
		return;

	msgserver = line_get_server(line);
	*list = completion_msg(server, msgserver, word, NULL);
	if (*list != NULL) signal_stop();
}

GList *completion_get_chatnets(const char *word)
{
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);

	len = strlen(word);
	list = NULL;

	for (tmp = chatnets; tmp != NULL; tmp = tmp->next) {
		CHATNET_REC *rec = tmp->data;

		if (g_strncasecmp(rec->name, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->name));
	}

	return list;
}

GList *completion_get_servers(const char *word)
{
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);

	len = strlen(word);
	list = NULL;

	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SERVER_SETUP_REC *rec = tmp->data;

		if (g_strncasecmp(rec->address, word, len) == 0) 
			list = g_list_append(list, g_strdup(rec->address));
	}

	return list;
}

static void sig_complete_connect(GList **list, WINDOW_REC *window,
				 const char *word, const char *line, 
				 int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	*list = completion_get_chatnets(word);
	*list = g_list_concat(*list, completion_get_servers(word));
	if (*list != NULL) signal_stop();
}

/* expand \n, \t and \\ */
static char *expand_escapes(const char *line, SERVER_REC *server,
			    WI_ITEM_REC *item)
{
	char *ptr, *ret;

	ret = ptr = g_malloc(strlen(line)+1);
	for (; *line != '\0'; line++) {
		if (*line != '\\') {
			*ptr++ = *line;
			continue;
		}

		line++;
		if (*line == '\0') {
			*ptr++ = '\\';
			break;
		}

		switch (*line) {
		case 'n':
			/* newline .. we need to send another "send text"
			   event to handle it (or actually the text before
			   the newline..) */
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

	*ptr = '\0';
	return ret;
}

static void event_text(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	CHANNEL_REC *channel;
	GList *comp;
	char *line, *str, *ptr, comp_char;

	g_return_if_fail(data != NULL);
	if (item == NULL) return;

	line = settings_get_bool("expand_escapes") ?
		expand_escapes(data, server, item) : g_strdup(data);
	comp_char = *settings_get_str("completion_char");

	/* check for automatic nick completion */
        ptr = NULL;
	comp = NULL;
	channel = CHANNEL(item);

	if (channel != NULL && comp_char != '\0' &&
	    settings_get_bool("completion_auto")) {
		ptr = strchr(line, comp_char);
		if (ptr != NULL) {
			*ptr++ = '\0';
			if (nicklist_find(channel, line) == NULL) {
				comp = completion_channel_nicks(channel,
								line, NULL);
			}
		}
	}

	str = g_strdup_printf(ptr == NULL ? "%s %s" : "%s %s%c%s", item->name,
			      comp != NULL ? (char *) comp->data : line,
			      comp_char, ptr);
	signal_emit("command msg", 3, str, server, item);

	g_free(str);
	g_free(line);

	if (comp != NULL) {
		g_list_foreach(comp, (GFunc) g_free, NULL);
		g_list_free(comp);
	}

	signal_stop();
}

static void sig_server_disconnected(SERVER_REC *server)
{
	g_return_if_fail(server != NULL);

	while (server->lastmsgs)
		SERVER_LAST_MSG_DESTROY(server, server->lastmsgs->data);
}

static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	while (channel->lastmsgs != NULL)
		last_msg_destroy(&channel->lastmsgs, channel->lastmsgs->data);
	while (channel->lastownmsgs != NULL)
		last_msg_destroy(&channel->lastownmsgs, channel->lastownmsgs->data);
}

void chat_completion_init(void)
{
	settings_add_str("completion", "completion_char", ":");
	settings_add_bool("completion", "completion_auto", FALSE);
	settings_add_int("completion", "completion_keep_publics", 180);
	settings_add_int("completion", "completion_keep_publics_count", 50);
	settings_add_int("completion", "completion_keep_ownpublics", 360);
	settings_add_int("completion", "completion_keep_privates", 10);
	settings_add_bool("completion", "expand_escapes", FALSE);
	settings_add_bool("completion", "completion_nicks_lowercase", FALSE);

	complete_tag = g_timeout_add(1000, (GSourceFunc) nick_completion_timeout, NULL);

	signal_add("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_add("complete command msg", (SIGNAL_FUNC) sig_complete_msg);
	signal_add("complete command connect", (SIGNAL_FUNC) sig_complete_connect);
	signal_add("complete command server", (SIGNAL_FUNC) sig_complete_connect);
	signal_add("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add("command msg", (SIGNAL_FUNC) cmd_msg);
	signal_add("nicklist remove", (SIGNAL_FUNC) sig_nick_removed);
	signal_add("nicklist changed", (SIGNAL_FUNC) sig_nick_changed);
	signal_add("send text", (SIGNAL_FUNC) event_text);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}

void chat_completion_deinit(void)
{
	g_source_remove(complete_tag);

	signal_remove("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_remove("complete command msg", (SIGNAL_FUNC) sig_complete_msg);
	signal_remove("complete command connect", (SIGNAL_FUNC) sig_complete_connect);
	signal_remove("complete command server", (SIGNAL_FUNC) sig_complete_connect);
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("command msg", (SIGNAL_FUNC) cmd_msg);
	signal_remove("nicklist remove", (SIGNAL_FUNC) sig_nick_removed);
	signal_remove("nicklist changed", (SIGNAL_FUNC) sig_nick_changed);
	signal_remove("send text", (SIGNAL_FUNC) event_text);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
}
