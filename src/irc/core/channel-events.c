/*
 channel-events.c : irssi

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
#include "signals.h"
#include "misc.h"
#include "channels-setup.h"
#include "settings.h"
#include "recode.h"

#include "irc-servers.h"
#include "irc-channels.h"

static void check_join_failure(IRC_SERVER_REC *server, const char *channel)
{
	CHANNEL_REC *chanrec;
	char *chan2;

	if (channel[0] == '!' && channel[1] == '!')
		channel++; /* server didn't understand !channels */

	chanrec = channel_find(SERVER(server), channel);
	if (chanrec == NULL && channel[0] == '!') {
		/* it probably replied with the full !channel name,
		   find the channel with the short name.. */
		chan2 = g_strdup_printf("!%s", channel+6);
		chanrec = channel_find(SERVER(server), chan2);
		g_free(chan2);
	}

	if (chanrec != NULL && !chanrec->joined) {
		chanrec->left = TRUE;
		channel_destroy(chanrec);
	}
}

static void irc_server_event(IRC_SERVER_REC *server, const char *line)
{
	char *params, *numeric, *channel;

	/* We'll be checking "4xx <your nick> <channel>" for channels
	   which we haven't joined yet. 4xx are error codes and should
	   indicate that the join failed. */
	params = event_get_params(line, 3, &numeric, NULL, &channel);

	if (numeric[0] == '4')
		check_join_failure(server, channel);

	g_free(params);
}

static void event_no_such_channel(IRC_SERVER_REC *server, const char *data)
{
	CHANNEL_REC *chanrec;
	CHANNEL_SETUP_REC *setup;
	char *params, *channel;

	params = event_get_params(data, 2, NULL, &channel);
	chanrec = *channel == '!' && channel[1] != '\0' ?
		channel_find(SERVER(server), channel) : NULL;

	if (chanrec != NULL) {
                /* !channel didn't exist, so join failed */
		setup = channel_setup_find(chanrec->name,
					   chanrec->server->connrec->chatnet);
		if (setup != NULL && setup->autojoin) {
			/* it's autojoin channel though, so create it */
			irc_send_cmdv(server, "JOIN !%s", chanrec->name);
			g_free(params);
                        return;
		}
	}

	check_join_failure(server, channel);
	g_free(params);
}

static void event_duplicate_channel(IRC_SERVER_REC *server, const char *data)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *p;

	g_return_if_fail(data != NULL);

	/* this new addition to ircd breaks completely with older
	   "standards", "nick Duplicate ::!!channel ...." */
	params = event_get_params(data, 3, NULL, NULL, &channel);
	p = strchr(channel, ' ');
	if (p != NULL) *p = '\0';

	if (channel[0] == '!') {
		chanrec = channel_find(SERVER(server),
				       channel+(channel[1] == '!'));
		if (chanrec != NULL && !chanrec->names_got) {
			chanrec->left = TRUE;
			channel_destroy(chanrec);
		}
	}

	g_free(params);
}

static void channel_change_topic(IRC_SERVER_REC *server, const char *channel,
				 const char *topic, const char *setby,
				 time_t settime)
{
	CHANNEL_REC *chanrec;
	char *recoded = NULL;
	
	chanrec = channel_find(SERVER(server), channel);
	if (chanrec == NULL) return;
	/* the topic may be send out encoded, so we need to 
	   recode it back or /topic <tab> will not work properly */
	recoded = recode_in(SERVER(server), topic, channel);
	if (topic != NULL) {
		g_free_not_null(chanrec->topic);
		chanrec->topic = recoded == NULL ? NULL : g_strdup(recoded);
	}
	g_free(recoded);

	g_free_not_null(chanrec->topic_by);
	chanrec->topic_by = g_strdup(setby);
	
	chanrec->topic_time = settime;

	signal_emit("channel topic changed", 1, chanrec);
}

static void event_topic_get(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel, *topic;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &topic);
	channel_change_topic(server, channel, topic, NULL, 0);
	g_free(params);
}

static void event_topic(IRC_SERVER_REC *server, const char *data,
			const char *nick, const char *addr)
{
	char *params, *channel, *topic, *mask;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, &channel, &topic);
	mask = addr == NULL ? g_strdup(nick) :
		g_strconcat(nick, "!", addr, NULL);
	channel_change_topic(server, channel, topic, mask, time(NULL));
	g_free(mask);
	g_free(params);
}

static void event_topic_info(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel, *topicby, *topictime;
	time_t t;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &channel,
				  &topicby, &topictime);

	t = (time_t) atol(topictime);
	channel_change_topic(server, channel, NULL, topicby, t);
	g_free(params);
}

/* Find any unjoined channel that matches `channel'. Long channel names are
   also a bit problematic, so find a channel where start of the name matches. */
static IRC_CHANNEL_REC *channel_find_unjoined(IRC_SERVER_REC *server,
					      const char *channel)
{
	GSList *tmp;
	int len;

	len = strlen(channel);
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		IRC_CHANNEL_REC *rec = tmp->data;

		if (!IS_IRC_CHANNEL(rec) || rec->joined)
			continue;

		if (g_strncasecmp(channel, rec->name, len) == 0 &&
		    (len > 20 || rec->name[len] == '\0'))
			return rec;
	}

	return NULL;
}

static void event_join(IRC_SERVER_REC *server, const char *data, const char *nick, const char *address)
{
	char *params, *channel, *tmp, *shortchan;
	IRC_CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);

	if (g_strcasecmp(nick, server->nick) != 0) {
		/* someone else joined channel, no need to do anything */
		return;
	}

	if (server->userhost == NULL)
		server->userhost = g_strdup(address);

	params = event_get_params(data, 1, &channel);
	tmp = strchr(channel, 7); /* ^G does something weird.. */
	if (tmp != NULL) *tmp = '\0';

	if (*channel != '!' || strlen(channel) < 7)
		shortchan = NULL;
	else {
		/* !channels have 5 chars long identification string before
		   it's name, it's not known when /join is called so rename
		   !channel here to !ABCDEchannel */
		shortchan = g_strdup_printf("!%s", channel+6);
		chanrec = channel_find_unjoined(server, shortchan);
		if (chanrec != NULL) {
			channel_change_name(CHANNEL(chanrec), channel);
			g_free(chanrec->name);
			chanrec->name = g_strdup(channel);
		} else {
			/* well, did we join it with full name? if so, and if
			   this was the first short one, change it's name. */
			chanrec = channel_find_unjoined(server, channel);
			if (chanrec != NULL &&
			    irc_channel_find(server, shortchan) == NULL) {
				channel_change_visible_name(CHANNEL(chanrec),
							    shortchan);
			}
		}
	}

	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL && chanrec->joined) {
		/* already joined this channel - probably a broken proxy that
		   forgot to send PART between */
		chanrec->left = TRUE;
		channel_destroy(CHANNEL(chanrec));
		chanrec = NULL;
	}

	if (chanrec == NULL) {
		/* look again, because of the channel name cut issues. */
		chanrec = channel_find_unjoined(server, channel);
	}

	if (chanrec == NULL) {
		/* didn't get here with /join command.. */
		chanrec = irc_channel_create(server, channel, shortchan, TRUE);
	}

	chanrec->joined = TRUE;
	if (strcmp(chanrec->name, channel) != 0) {
                g_free(chanrec->name);
		chanrec->name = g_strdup(channel);
	}

	g_free(shortchan);
	g_free(params);
}

static void event_part(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	char *params, *channel, *reason;
	CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);

	if (g_strcasecmp(nick, server->nick) != 0) {
		/* someone else part, no need to do anything here */
		return;
	}

	params = event_get_params(data, 2, &channel, &reason);

	chanrec = channel_find(SERVER(server), channel);
	if (chanrec != NULL && chanrec->joined) {
		chanrec->left = TRUE;
		channel_destroy(chanrec);
	}

	g_free(params);
}

static void event_kick(IRC_SERVER_REC *server, const char *data)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *nick, *reason;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, &channel, &nick, &reason);

	if (g_strcasecmp(nick, server->nick) != 0) {
		/* someone else was kicked, no need to do anything */
		g_free(params);
		return;
	}

	chanrec = channel_find(SERVER(server), channel);
	if (chanrec != NULL) {
		irc_server_purge_output(server, channel);
		chanrec->kicked = TRUE;
		channel_destroy(chanrec);
	}

	g_free(params);
}

static void event_invite(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel, *shortchan;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	if (irc_channel_find(server, channel) == NULL) {
                /* check if we're supposed to autojoin this channel */
		CHANNEL_SETUP_REC *setup;

		setup = channel_setup_find(channel, server->connrec->chatnet);
		if (setup == NULL && channel[0] == '!' &&
		    strlen(channel) > 6) {
			shortchan = g_strdup_printf("!%s", channel+6);
			setup = channel_setup_find(shortchan,
						   server->connrec->chatnet);
			g_free(shortchan);
		}
		if (setup != NULL && setup->autojoin && settings_get_bool("join_auto_chans_on_invite"))
			server->channels_join(SERVER(server), channel, TRUE);
	}

	g_free_not_null(server->last_invite);
	server->last_invite = g_strdup(channel);
	g_free(params);
}

void channel_events_init(void)
{
	settings_add_bool("misc", "join_auto_chans_on_invite", TRUE);

	signal_add_last("server event", (SIGNAL_FUNC) irc_server_event);
	signal_add_first("event 403", (SIGNAL_FUNC) event_no_such_channel); /* no such channel */
	signal_add_first("event 407", (SIGNAL_FUNC) event_duplicate_channel); /* duplicate channel */

	signal_add("event topic", (SIGNAL_FUNC) event_topic);
	signal_add_first("event join", (SIGNAL_FUNC) event_join);
	signal_add("event part", (SIGNAL_FUNC) event_part);
	signal_add("event kick", (SIGNAL_FUNC) event_kick);
	signal_add("event invite", (SIGNAL_FUNC) event_invite);
	signal_add("event 332", (SIGNAL_FUNC) event_topic_get);
	signal_add("event 333", (SIGNAL_FUNC) event_topic_info);
}

void channel_events_deinit(void)
{
	signal_remove("server event", (SIGNAL_FUNC) irc_server_event);
	signal_remove("event 403", (SIGNAL_FUNC) event_no_such_channel); /* no such channel */
	signal_remove("event 407", (SIGNAL_FUNC) event_duplicate_channel); /* duplicate channel */

	signal_remove("event topic", (SIGNAL_FUNC) event_topic);
	signal_remove("event join", (SIGNAL_FUNC) event_join);
	signal_remove("event part", (SIGNAL_FUNC) event_part);
	signal_remove("event kick", (SIGNAL_FUNC) event_kick);
	signal_remove("event invite", (SIGNAL_FUNC) event_invite);
	signal_remove("event 332", (SIGNAL_FUNC) event_topic_get);
	signal_remove("event 333", (SIGNAL_FUNC) event_topic_info);
}
