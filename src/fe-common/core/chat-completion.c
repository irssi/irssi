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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/lib-config/iconfig.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/channels-setup.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/nicklist.h>

#include <irssi/src/fe-common/core/completion.h>
#include <irssi/src/fe-common/core/chat-completion.h>
#include <irssi/src/fe-common/core/window-items.h>

enum {
	COMPLETE_MCASE_NEVER = 0,
	COMPLETE_MCASE_ALWAYS,
	COMPLETE_MCASE_AUTO,
};

static int keep_privates_count, keep_publics_count;
static int completion_lowercase;
static char *completion_char, *cmdchars;
static GSList *global_lastmsgs;
static int completion_auto, completion_strict, completion_empty_line;
static int completion_match_case;

#define SERVER_LAST_MSG_ADD(server, nick) \
	last_msg_add(&((MODULE_SERVER_REC *) MODULE_DATA(server))->lastmsgs, \
		     nick, TRUE, keep_privates_count)

#define CHANNEL_LAST_MSG_ADD(channel, nick, own) \
	last_msg_add(&((MODULE_CHANNEL_REC *) MODULE_DATA(channel))->lastmsgs, \
		     nick, own, keep_publics_count)

static gboolean contains_uppercase(const char *s1)
{
	const char *ch;

	for (ch = s1; *ch != '\0'; ch++) {
		if (g_ascii_isupper(*ch))
			return TRUE;
	}

	return FALSE;
}

static LAST_MSG_REC *last_msg_find(GSList *list, const char *nick)
{
	while (list != NULL) {
		LAST_MSG_REC *rec = list->data;

		if (g_ascii_strcasecmp(rec->nick, nick) == 0)
			return rec;
		list = list->next;
	}

	return NULL;
}

static void last_msg_dec_owns(GSList *list)
{
	LAST_MSG_REC *rec;

	while (list != NULL) {
		rec = list->data;
		if (rec->own) rec->own--;

		list = list->next;
	}
}

static void last_msg_destroy(GSList **list, LAST_MSG_REC *rec)
{
	*list = g_slist_remove(*list, rec);

	g_free(rec->nick);
	g_free(rec);
}

static void last_msg_add(GSList **list, const char *nick, int own, int max)
{
	LAST_MSG_REC *rec;

	if (max <= 0)
		return;

	rec = last_msg_find(*list, nick);
	if (rec != NULL) {
		/* msg already exists, update it */
		*list = g_slist_remove(*list, rec);
		if (own)
			rec->own = max;
		else if (rec->own)
                        rec->own--;
	} else {
		rec = g_new(LAST_MSG_REC, 1);
		rec->nick = g_strdup(nick);

		while ((int)g_slist_length(*list) >= max) {
			last_msg_destroy(list, g_slist_last(*list)->data);
		}

		rec->own = own ? max : 0;
	}
	rec->time = time(NULL);

        last_msg_dec_owns(*list);

	*list = g_slist_prepend(*list, rec);
}

void completion_last_message_add(const char *nick)
{
	g_return_if_fail(nick != NULL);

	last_msg_add(&global_lastmsgs, nick, TRUE, keep_privates_count);
}

void completion_last_message_remove(const char *nick)
{
	LAST_MSG_REC *rec;

	g_return_if_fail(nick != NULL);

	rec = last_msg_find(global_lastmsgs, nick);
        if (rec != NULL) last_msg_destroy(&global_lastmsgs, rec);
}

void completion_last_message_rename(const char *oldnick, const char *newnick)
{
	LAST_MSG_REC *rec;

	g_return_if_fail(oldnick != NULL);
	g_return_if_fail(newnick != NULL);

	rec = last_msg_find(global_lastmsgs, oldnick);
	if (rec != NULL) {
		g_free(rec->nick);
                rec->nick = g_strdup(newnick);
	}
}

static void sig_message_public(SERVER_REC *server, const char *msg,
			       const char *nick, const char *address,
			       const char *target)
{
	CHANNEL_REC *channel;
        int own;
	g_return_if_fail(nick != NULL);

	channel = channel_find(server, target);
	if (channel != NULL) {
                own = nick_match_msg(channel, msg, server->nick);
		CHANNEL_LAST_MSG_ADD(channel, nick, own);
	}
}

static void sig_message_join(SERVER_REC *server, const char *channel,
			     const char *nick, const char *address)
{
	CHANNEL_REC *chanrec;
	g_return_if_fail(nick != NULL);

	chanrec = channel_find(server, channel);
	if (chanrec != NULL)
		CHANNEL_LAST_MSG_ADD(chanrec, nick, FALSE);
}

static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *address)
{
	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	SERVER_LAST_MSG_ADD(server, nick);
}

static void sig_message_own_public(SERVER_REC *server, const char *msg,
				   const char *target, const char *origtarget)
{
	CHANNEL_REC *channel;
	NICK_REC *nick;
	char *p, *msgnick;

	g_return_if_fail(server != NULL);
	g_return_if_fail(msg != NULL);
        if (target == NULL) return;

        channel = channel_find(server, target);
	if (channel == NULL)
		return;

	/* channel msg - if first word in line is nick,
	   add it to lastmsgs */
	p = strchr(msg, ' ');
	if (p != NULL && p != msg) {
		msgnick = g_strndup(msg, (int) (p-msg));
		nick = nicklist_find(channel, msgnick);
		if (nick == NULL && msgnick[1] != '\0') {
			/* probably ':' or ',' or some other
			   char after nick, try without it */
			msgnick[strlen(msgnick)-1] = '\0';
			nick = nicklist_find(channel, msgnick);
		}
                g_free(msgnick);
		if (nick != NULL && nick != channel->ownnick)
			CHANNEL_LAST_MSG_ADD(channel, nick->nick, TRUE);
	}
}

static void sig_message_own_private(SERVER_REC *server, const char *msg,
				    const char *target, const char *origtarget)
{
	g_return_if_fail(server != NULL);

	if (target != NULL && query_find(server, target) == NULL)
		SERVER_LAST_MSG_ADD(server, target);
}

static void sig_nick_removed(CHANNEL_REC *channel, NICK_REC *nick)
{
        MODULE_CHANNEL_REC *mchannel;
	LAST_MSG_REC *rec;

        mchannel = MODULE_DATA(channel);
	rec = last_msg_find(mchannel->lastmsgs, nick->nick);
	if (rec != NULL) last_msg_destroy(&mchannel->lastmsgs, rec);
}

static void sig_nick_changed(CHANNEL_REC *channel, NICK_REC *nick,
			     const char *oldnick)
{
        MODULE_CHANNEL_REC *mchannel;
	LAST_MSG_REC *rec;

        mchannel = MODULE_DATA(channel);
	rec = last_msg_find(mchannel->lastmsgs, oldnick);
	if (rec != NULL) {
		g_free(rec->nick);
		rec->nick = g_strdup(nick->nick);
	}
}

static int last_msg_cmp(LAST_MSG_REC *m1, LAST_MSG_REC *m2)
{
	return m1->time < m2->time ? 1 : -1;
}

/* Complete /MSG from specified server, or from
   global_lastmsgs if server is NULL */
static void completion_msg_server(GSList **list, SERVER_REC *server,
				  const char *nick, const char *prefix)
{
	LAST_MSG_REC *msg;
	GSList *tmp;
	int len;

	g_return_if_fail(nick != NULL);

	len = strlen(nick);
	tmp = server == NULL ? global_lastmsgs :
		((MODULE_SERVER_REC *) MODULE_DATA(server))->lastmsgs;
	for (; tmp != NULL; tmp = tmp->next) {
		LAST_MSG_REC *rec = tmp->data;

		if (len != 0 && g_ascii_strncasecmp(rec->nick, nick, len) != 0)
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
GList *completion_msg(SERVER_REC *win_server,
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

	completion_msg_server(&list, NULL, nick, prefix);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		if (servers->next == NULL && rec == win_server)
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

static void complete_from_nicklist(GList **outlist, CHANNEL_REC *channel,
				   const char *nick, const char *suffix,
				   const int match_case)
{
        MODULE_CHANNEL_REC *mchannel;
	GSList *tmp;
        GList *ownlist;
	char *str;
	int len;

	/* go through the last x nicks who have said something in the channel.
	   nicks of all the "own messages" are placed before others */
        ownlist = NULL;
	len = strlen(nick);
        mchannel = MODULE_DATA(channel);
	for (tmp = mchannel->lastmsgs; tmp != NULL; tmp = tmp->next) {
		LAST_MSG_REC *rec = tmp->data;

		if ((match_case ? strncmp(rec->nick, nick, len) :
		                  g_ascii_strncasecmp(rec->nick, nick, len)) == 0 &&
		    (match_case ? i_list_find_string(*outlist, rec->nick) :
		                  i_list_find_icase_string(*outlist, rec->nick)) == NULL) {
			str = g_strconcat(rec->nick, suffix, NULL);
			if (completion_lowercase) ascii_strdown(str);
			if (rec->own)
				ownlist = g_list_append(ownlist, str);
                        else
				*outlist = g_list_append(*outlist, str);
		}
	}

        *outlist = g_list_concat(ownlist, *outlist);
}

static GList *completion_nicks_nonstrict(CHANNEL_REC *channel,
					 const char *nick,
					 const char *suffix,
					 const int match_case)
{
	GSList *nicks, *tmp;
	GList *list;
	char *tnick, *str, *in, *out;
	int len, str_len, tmplen;

	g_return_val_if_fail(channel != NULL, NULL);

	list = NULL;

	/* get all nicks from current channel, strip non alnum chars,
	   compare again and add to completion list on matching */
	len = strlen(nick);
	nicks = nicklist_getnicks(channel);

	str_len = 80; str = g_malloc(str_len+1);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

                tmplen = strlen(rec->nick);
		if (tmplen > str_len) {
                        str_len = tmplen*2;
                        str = g_realloc(str, str_len+1);
		}

		/* remove non alnum chars from nick */
		in = rec->nick; out = str;
		while (*in != '\0') {
			if (i_isalnum(*in))
				*out++ = *in;
                        in++;
		}
                *out = '\0';

		/* add to list if 'cleaned' nick matches */
		if ((match_case? strncmp(str, nick, len)
		     : g_ascii_strncasecmp(str, nick, len)) == 0) {
			tnick = g_strconcat(rec->nick, suffix, NULL);
			if (completion_lowercase)
				ascii_strdown(tnick);

			if (i_list_find_icase_string(list, tnick) == NULL)
				list = g_list_append(list, tnick);
			else
                                g_free(tnick);
		}

	}
        g_free(str);
	g_slist_free(nicks);

	return list;
}

static GList *completion_channel_nicks(CHANNEL_REC *channel, const char *nick,
				       const char *suffix)
{
	GSList *nicks, *tmp;
	GList *list;
	char *str;
	int len, match_case;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);
	if (*nick == '\0') return NULL;

	if (suffix != NULL && *suffix == '\0')
		suffix = NULL;

	match_case = completion_match_case == COMPLETE_MCASE_ALWAYS ||
		(completion_match_case == COMPLETE_MCASE_AUTO && contains_uppercase(nick));

	/* put first the nicks who have recently said something */
	list = NULL;
	complete_from_nicklist(&list, channel, nick, suffix, match_case);

	/* and add the rest of the nicks too */
	len = strlen(nick);
	nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		if ((match_case? strncmp(rec->nick, nick, len)
		     : g_ascii_strncasecmp(rec->nick, nick, len)) == 0 &&
		    rec != channel->ownnick) {
			str = g_strconcat(rec->nick, suffix, NULL);
			if (completion_lowercase)
				ascii_strdown(str);
			if (i_list_find_icase_string(list, str) == NULL)
				list = g_list_append(list, str);
			else
                                g_free(str);
		}
	}
	g_slist_free(nicks);

	/* remove non alphanum chars from nick and search again in case
	   list is still NULL ("foo<tab>" would match "_foo_" f.e.) */
	if (!completion_strict)
		list = g_list_concat(list, completion_nicks_nonstrict(channel, nick, suffix, match_case));
	return list;
}

/* append all strings in list2 to list1 that already aren't there and
   free list2 */
static GList *completion_joinlist(GList *list1, GList *list2)
{
	GList *old;

	old = list2;
	while (list2 != NULL) {
		if (!i_list_find_icase_string(list1, list2->data))
			list1 = g_list_append(list1, list2->data);
		else
			g_free(list2->data);

		list2 = list2->next;
	}

	g_list_free(old);
	return list1;
}

GList *completion_get_servertags(const char *word)
{
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);

	len = strlen(word);
	list = NULL;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		if (g_ascii_strncasecmp(rec->tag, word, len) == 0) {
			if (rec == active_win->active_server)
				list = g_list_prepend(list, g_strdup(rec->tag));
			else
				list = g_list_append(list, g_strdup(rec->tag));
		}

	}

	return list;
}

GList *completion_get_channels(SERVER_REC *server, const char *word)
{
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);

	len = strlen(word);
	list = NULL;

	/* first get the joined channels */
	tmp = server == NULL ? NULL : server->channels;
	for (; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (g_ascii_strncasecmp(rec->visible_name, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->visible_name));
		else if (g_ascii_strncasecmp(rec->name, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->name));
	}

	/* get channels from setup */
	for (tmp = setupchannels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_SETUP_REC *rec = tmp->data;

		if (g_ascii_strncasecmp(rec->name, word, len) == 0 &&
		    i_list_find_icase_string(list, rec->name) == NULL)
			list = g_list_append(list, g_strdup(rec->name));

	}

	return list;
}

GList *completion_get_aliases(const char *word)
{
	CONFIG_NODE *node;
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);

	len = strlen(word);
	list = NULL;

	/* get the list of all aliases */
	node = iconfig_node_traverse("aliases", FALSE);
	tmp = node == NULL ? NULL : config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;

		if (node->type != NODE_TYPE_KEY)
			continue;

		if (len != 0 && g_ascii_strncasecmp(node->key, word, len) != 0)
			continue;

		list = g_list_append(list, g_strdup(node->key));
	}

	return list;
}

static void complete_window_nicks(GList **list, WINDOW_REC *window,
                                  const char *word, const char *nicksuffix)
{
        CHANNEL_REC *channel;
        GList *tmplist;
        GSList *tmp;

        channel = CHANNEL(window->active);

        /* first the active channel */
        if (channel != NULL) {
                tmplist = completion_channel_nicks(channel, word, nicksuffix);
                *list = completion_joinlist(*list, tmplist);
        }

        if (nicksuffix != NULL) {
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
                                                           nicksuffix);
                        *list = completion_joinlist(*list, tmplist);
                }
        }
}

/* Checks if a line is only nicks from autocompletion.
   This lets us insert colons only at the beginning of a list
   of nicks */
static int only_nicks(const char *linestart)
{
	int i = 1;
	char prev;

	// at the beginning of the line
	if (*linestart == '\0') {
		return TRUE;
	}

	/* completion_char being a whole string introduces loads of edge cases
	   and can't be handled generally. Skip this case; we handled the
	   "beginning of line" case already */
	if (completion_char[1] != '\0')
		return FALSE;

	/* This would make the completion char get inserted everywhere otherwise */
	if (*completion_char == ' ')
		return FALSE;

	/* First ensure that the line is of the format "foo: bar: baz"
	   we check this by ensuring each space is preceded by a colon or
	   another space */
	while (linestart[i] != '\0') {
		if (linestart[i] == ' ') {
			prev = linestart[i - 1];
			if (prev != *completion_char && prev != ' ')
				return FALSE;
		}
		i += 1;
	}

	/* There's an edge case here, if we're completing something
	   like `foo: bar ba<tab>`, then the `linestart` line will end
	   at "bar", and we'll miss the space. Ensure that the end
	   of the line is a colon followed by an optional series of spaces */
	i -= 1;
	while (i >= 0) {
		if (linestart[i] == ' ') {
			i--;
			continue;
		} else if (linestart[i] == *completion_char) {
			return TRUE;
		} else {
			break;
		}
	}
	return FALSE;
}

static void sig_complete_word(GList **list, WINDOW_REC *window,
			      const char *word, const char *linestart,
			      int *want_space)
{
	SERVER_REC *server;
	CHANNEL_REC *channel;
	QUERY_REC *query;
	char *prefix;

	g_return_if_fail(list != NULL);
	g_return_if_fail(window != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(linestart != NULL);

	server = window->active_server;
	if (server == NULL && servers != NULL)
		server = servers->data;

	if (server != NULL && server_ischannel(server, word)) {
		/* probably completing a channel name */
		*list = completion_get_channels(window->active_server, word);
		if (*list != NULL) signal_stop();
                return;
	}

	server = window->active_server;
	if (server == NULL || !server->connected)
		return;

	if (*linestart == '\0' && *word == '\0') {
		if (!completion_empty_line)
			return;
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
	if (channel == NULL && query != NULL &&
	    g_ascii_strncasecmp(word, query->name, strlen(word)) == 0) {
		/* completion in query */
                *list = g_list_append(*list, g_strdup(query->name));
	} else if (channel != NULL) {
		/* nick completion .. we could also be completing a nick
		   after /MSG from nicks in channel */
		const char *suffix = only_nicks(linestart) ? completion_char : NULL;
		complete_window_nicks(list, window, word, suffix);
	} else if (window->level & MSGLEVEL_MSGS) {
		/* msgs window, complete /MSG nicks */
                *list = g_list_concat(completion_msg(server, NULL, word, NULL), *list);
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
	if (CHANNEL(window->active) != NULL)
		complete_window_nicks(list, window, word, NULL);
	if (*list != NULL) signal_stop();
}

static void sig_erase_complete_msg(WINDOW_REC *window, const char *word,
				   const char *line)
{
	SERVER_REC *server;
	MODULE_SERVER_REC *mserver;
        GSList *tmp;

	server = line_get_server(line);
	if (server == NULL){
		server = window->active_server;
		if (server == NULL)
                        return;
	}

	if (*word == '\0')
		return;

        /* check from global list */
	completion_last_message_remove(word);

	/* check from server specific list */
	if (server != NULL) {
		mserver = MODULE_DATA(server);
		for (tmp = mserver->lastmsgs; tmp != NULL; tmp = tmp->next) {
			LAST_MSG_REC *rec = tmp->data;

			if (g_ascii_strcasecmp(rec->nick, word) == 0) {
				last_msg_destroy(&mserver->lastmsgs, rec);
                                break;
			}
		}

	}
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

		if (g_ascii_strncasecmp(rec->name, word, len) == 0)
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

		if (g_ascii_strncasecmp(rec->address, word, len) == 0)
			list = g_list_append(list, g_strdup(rec->address));
	}

	return list;
}

GList *completion_get_targets(const char *word)
{
	CONFIG_NODE *node;
	GList *list;
	GSList *tmp;
	int len;

	g_return_val_if_fail(word != NULL, NULL);

	len = strlen(word);
	list = NULL;

	/* get the list of all conversion targets */
	node = iconfig_node_traverse("conversions", FALSE);
	tmp = node == NULL ? NULL : config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;

		if (node->type != NODE_TYPE_KEY)
			continue;

		if (len != 0 && g_ascii_strncasecmp(node->key, word, len) != 0)
			continue;

		list = g_list_append(list, g_strdup(node->key));
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

static void sig_complete_tag(GList **list, WINDOW_REC *window,
			     const char *word, const char *line,
			     int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	*list = completion_get_servertags(word);
	if (*list != NULL) signal_stop();
}

static void sig_complete_topic(GList **list, WINDOW_REC *window,
			       const char *word, const char *line,
			       int *want_space)
{
	const char *topic;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	if (*word == '\0' && IS_CHANNEL(window->active)) {
		topic = CHANNEL(window->active)->topic;
		if (topic != NULL) {
			*list = g_list_append(NULL, g_strdup(topic));
                        signal_stop();
		}
	}
}

static void sig_complete_away(GList **list, WINDOW_REC *window,
			       const char *word, const char *line,
			       int *want_space)
{
	const char *reason;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

        *want_space = FALSE;

	if (*word == '\0' && window->active_server != NULL) {
		reason = SERVER(window->active_server)->away_reason;
		if (reason != NULL) {
			*list = g_list_append(NULL, g_strdup(reason));
			signal_stop();
		}
	}
}

static void sig_complete_unalias(GList **list, WINDOW_REC *window,
				const char *word, const char *line,
				int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	*list = completion_get_aliases(word);
	if (*list != NULL) signal_stop();
}

static void sig_complete_alias(GList **list, WINDOW_REC *window,
				const char *word, const char *line,
				int *want_space)
{
	const char *definition;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line != '\0') {
		if ((definition = alias_find(line)) != NULL) {
			*list = g_list_append(NULL, g_strdup(definition));
			signal_stop();
		}
	} else {
		*list = completion_get_aliases(word);
		if (*list != NULL) signal_stop();
	}
}

static void sig_complete_window(GList **list, WINDOW_REC *window,
				const char *word, const char *linestart,
				int *want_space)
{
	WINDOW_REC *win;
	WI_ITEM_REC *item;
	GSList *tmp;
	int len;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	len = strlen(word);

	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		win = tmp->data;
		item = win->active;

		if (win->name != NULL && g_ascii_strncasecmp(win->name, word, len) == 0)
			*list = g_list_append(*list, g_strdup(win->name));
		if (item != NULL && g_ascii_strncasecmp(item->visible_name, word, len) == 0)
			*list = g_list_append(*list, g_strdup(item->visible_name));
	}

	if (*list != NULL) signal_stop();
}

static void sig_complete_channel(GList **list, WINDOW_REC *window,
				 const char *word, const char *line,
				 int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	*list = completion_get_channels(NULL, word);
	if (*list != NULL) signal_stop();
}

static void sig_complete_server(GList **list, WINDOW_REC *window,
				const char *word, const char *line,
				int *want_space)
{
	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);

	*list = completion_get_servers(word);
	if (*list != NULL) signal_stop();
}

static void sig_complete_target(GList **list, WINDOW_REC *window,
				const char *word, const char *line,
				int *want_space)
{
	const char *definition;

	g_return_if_fail(list != NULL);
	g_return_if_fail(word != NULL);
	g_return_if_fail(line != NULL);

	if (*line != '\0') {
		if ((definition = iconfig_get_str("conversions", line ,NULL)) != NULL) {
			*list = g_list_append(NULL, g_strdup(definition));
			signal_stop();
		}
	} else {
		*list = completion_get_targets(word);
		if (*list != NULL) signal_stop();
	}
}

static void event_text(const char *data, SERVER_REC *server, WI_ITEM_REC *item);

/* expand \n, \t and \\ */
static char *expand_escapes(const char *line, SERVER_REC *server,
			    WI_ITEM_REC *item)
{
	char *ptr, *ret;
	const char *prev;
	int chr;

	prev = line;
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

		chr = expand_escape(&line);
		if (chr == '\r' || chr == '\n') {
			/* newline .. we need to send another "send text"
			   event to handle it (or actually the text before
			   the newline..) */
			if (prev != line) {
				char *prev_line = g_strndup(prev, (line - prev) - 1);
				event_text(prev_line, server, item);
				g_free(prev_line);
				prev = line + 1;
				ptr = ret;
			}
		} else if (chr != -1) {
                        /* escaping went ok */
			*ptr++ = chr;
		} else {
                        /* unknown escape, add it as-is */
			*ptr++ = '\\';
			*ptr++ = *line;
		}
	}

	*ptr = '\0';
	return ret;
}

static char *auto_complete(CHANNEL_REC *channel, const char *line)
{
	GList *comp;
	const char *p;
        char *nick, *ret;

	p = strstr(line, completion_char);
	if (p == NULL)
		return NULL;

        nick = g_strndup(line, (int) (p-line));

        ret = NULL;
	if (nicklist_find(channel, nick) == NULL) {
                /* not an exact match, use the first possible completion */
		comp = completion_channel_nicks(channel, nick, NULL);
		if (comp != NULL) {
			ret = g_strconcat(comp->data, p, NULL);
			g_list_foreach(comp, (GFunc) g_free, NULL);
			g_list_free(comp);
		}
	}

	g_free(nick);

        return ret;
}

static void event_text(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	char *line, *str, *target;

	g_return_if_fail(data != NULL);

	if (item == NULL)
		return;

	if (*data == '\0') {
		/* empty line, forget it. */
                signal_stop();
		return;
	}

	line = settings_get_bool("expand_escapes") ?
		expand_escapes(data, server, item) : g_strdup(data);

	/* check for automatic nick completion */
	if (completion_auto && IS_CHANNEL(item)) {
		str = auto_complete(CHANNEL(item), line);
		if (str != NULL) {
			g_free(line);
                        line = str;
		}
	}

	/* the nick is quoted in case it contains '-' character. also
	   spaces should work too now :) The nick is also escaped in case
	   it contains '\' characters */
	target = escape_string(window_item_get_target(item));
	str = g_strdup_printf(IS_CHANNEL(item) ? "-channel \"%s\" %s" :
			      IS_QUERY(item) ? "-nick \"%s\" %s" : "%s %s",
			      target, line);
	g_free(target);

	signal_emit("command msg", 3, str, server, item);

	g_free(str);
	g_free(line);

	signal_stop();
}

static void sig_server_disconnected(SERVER_REC *server)
{
	MODULE_SERVER_REC *mserver;

	g_return_if_fail(server != NULL);

        mserver = MODULE_DATA(server);
	if (mserver == NULL)
		return;

	while (mserver->lastmsgs)
                last_msg_destroy(&mserver->lastmsgs, mserver->lastmsgs->data);
}

static void sig_channel_destroyed(CHANNEL_REC *channel)
{
	MODULE_CHANNEL_REC *mchannel;

	g_return_if_fail(channel != NULL);

        mchannel = MODULE_DATA(channel);
	while (mchannel->lastmsgs != NULL) {
		last_msg_destroy(&mchannel->lastmsgs,
				 mchannel->lastmsgs->data);
	}
}

static void read_settings(void)
{
	keep_privates_count = settings_get_int("completion_keep_privates");
	keep_publics_count = settings_get_int("completion_keep_publics");
	completion_lowercase = settings_get_bool("completion_nicks_lowercase");

	completion_auto = settings_get_bool("completion_auto");
	completion_strict = settings_get_bool("completion_strict");
	completion_empty_line = settings_get_bool("completion_empty_line");

	completion_match_case = settings_get_choice("completion_nicks_match_case");

	g_free_not_null(completion_char);
	completion_char = g_strdup(settings_get_str("completion_char"));

	g_free_not_null(cmdchars);
	cmdchars = g_strdup(settings_get_str("cmdchars"));

	if (*completion_char == '\0') {
                /* this would break.. */
		completion_auto = FALSE;
	}
}

void chat_completion_init(void)
{
	settings_add_str("completion", "completion_char", ":");
	settings_add_bool("completion", "completion_auto", FALSE);
	settings_add_int("completion", "completion_keep_publics", 50);
	settings_add_int("completion", "completion_keep_privates", 10);
	settings_add_bool("completion", "completion_nicks_lowercase", FALSE);
	settings_add_bool("completion", "completion_strict", FALSE);
	settings_add_bool("completion", "completion_empty_line", TRUE);
	settings_add_choice("completion", "completion_nicks_match_case", COMPLETE_MCASE_AUTO, "never;always;auto");

	settings_add_bool("lookandfeel", "expand_escapes", FALSE);

	read_settings();
	signal_add("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_add("complete command msg", (SIGNAL_FUNC) sig_complete_msg);
	signal_add("complete command query", (SIGNAL_FUNC) sig_complete_msg);
	signal_add("complete command action", (SIGNAL_FUNC) sig_complete_msg);
	signal_add("complete erase command msg", (SIGNAL_FUNC) sig_erase_complete_msg);
	signal_add("complete erase command query", (SIGNAL_FUNC) sig_erase_complete_msg);
	signal_add("complete erase command action", (SIGNAL_FUNC) sig_erase_complete_msg);
	signal_add("complete command connect", (SIGNAL_FUNC) sig_complete_connect);
	signal_add("complete command server", (SIGNAL_FUNC) sig_complete_connect);
	signal_add("complete command disconnect", (SIGNAL_FUNC) sig_complete_tag);
	signal_add("complete command reconnect", (SIGNAL_FUNC) sig_complete_tag);
	signal_add("complete command window server", (SIGNAL_FUNC) sig_complete_tag);
	signal_add("complete command topic", (SIGNAL_FUNC) sig_complete_topic);
	signal_add("complete command away", (SIGNAL_FUNC) sig_complete_away);
	signal_add("complete command unalias", (SIGNAL_FUNC) sig_complete_unalias);
	signal_add("complete command alias", (SIGNAL_FUNC) sig_complete_alias);
	signal_add("complete command window goto", (SIGNAL_FUNC) sig_complete_window);
	signal_add("complete command window item move", (SIGNAL_FUNC) sig_complete_channel);
	signal_add("complete command server add", (SIGNAL_FUNC) sig_complete_server);
	signal_add("complete command server remove", (SIGNAL_FUNC) sig_complete_server);
	signal_add("complete command recode remove", (SIGNAL_FUNC) sig_complete_target);
	signal_add("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add("message join", (SIGNAL_FUNC) sig_message_join);
	signal_add("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add("message own_public", (SIGNAL_FUNC) sig_message_own_public);
	signal_add("message own_private", (SIGNAL_FUNC) sig_message_own_private);
	signal_add("nicklist remove", (SIGNAL_FUNC) sig_nick_removed);
	signal_add("nicklist changed", (SIGNAL_FUNC) sig_nick_changed);
	signal_add("send text", (SIGNAL_FUNC) event_text);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void chat_completion_deinit(void)
{
	while (global_lastmsgs != NULL)
		last_msg_destroy(&global_lastmsgs, global_lastmsgs->data);

	signal_remove("complete word", (SIGNAL_FUNC) sig_complete_word);
	signal_remove("complete command msg", (SIGNAL_FUNC) sig_complete_msg);
	signal_remove("complete command query", (SIGNAL_FUNC) sig_complete_msg);
	signal_remove("complete command action", (SIGNAL_FUNC) sig_complete_msg);
	signal_remove("complete erase command msg", (SIGNAL_FUNC) sig_erase_complete_msg);
	signal_remove("complete erase command query", (SIGNAL_FUNC) sig_erase_complete_msg);
	signal_remove("complete erase command action", (SIGNAL_FUNC) sig_erase_complete_msg);
	signal_remove("complete command connect", (SIGNAL_FUNC) sig_complete_connect);
	signal_remove("complete command server", (SIGNAL_FUNC) sig_complete_connect);
	signal_remove("complete command disconnect", (SIGNAL_FUNC) sig_complete_tag);
	signal_remove("complete command reconnect", (SIGNAL_FUNC) sig_complete_tag);
	signal_remove("complete command window server", (SIGNAL_FUNC) sig_complete_tag);
	signal_remove("complete command topic", (SIGNAL_FUNC) sig_complete_topic);
	signal_remove("complete command away", (SIGNAL_FUNC) sig_complete_away);
	signal_remove("complete command unalias", (SIGNAL_FUNC) sig_complete_unalias);
	signal_remove("complete command alias", (SIGNAL_FUNC) sig_complete_alias);
	signal_remove("complete command window goto", (SIGNAL_FUNC) sig_complete_window);
	signal_remove("complete command window item move", (SIGNAL_FUNC) sig_complete_channel);
	signal_remove("complete command server add", (SIGNAL_FUNC) sig_complete_server);
	signal_remove("complete command server remove", (SIGNAL_FUNC) sig_complete_server);
	signal_remove("complete command recode remove", (SIGNAL_FUNC) sig_complete_target);
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message join", (SIGNAL_FUNC) sig_message_join);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("message own_public", (SIGNAL_FUNC) sig_message_own_public);
	signal_remove("message own_private", (SIGNAL_FUNC) sig_message_own_private);
	signal_remove("nicklist remove", (SIGNAL_FUNC) sig_nick_removed);
	signal_remove("nicklist changed", (SIGNAL_FUNC) sig_nick_changed);
	signal_remove("send text", (SIGNAL_FUNC) event_text);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	g_free_not_null(completion_char);
	g_free_not_null(cmdchars);
}
