/*
 fe-events-numeric.c : irssi

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
#include "misc.h"
#include "settings.h"

#include "irc.h"
#include "levels.h"
#include "servers.h"
#include "irc-channels.h"
#include "nicklist.h"

static char *last_away_nick = NULL;
static char *last_away_msg = NULL;

static void event_user_mode(const char *data, IRC_SERVER_REC *server)
{
	char *params, *mode;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &mode);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_USER_MODE, mode);
	g_free(params);
}

static void event_ison(const char *data, IRC_SERVER_REC *server)
{
	char *params, *online;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &online);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_ONLINE, online);
	g_free(params);
}

static void event_names_list(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *names;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, NULL, &channel, &names);
	if (irc_channel_find(server, channel) == NULL)
		printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_NAMES, channel, names);
	g_free(params);
}

static void display_sorted_nicks(CHANNEL_REC *channel, GSList *nicklist, gint items, gint max)
{
    NICK_REC *rec, *last;
    GString *str;
    GSList *tmp;
    gint lines, cols, line, col, skip;
    gchar *linebuf;

    max++; /* op/voice */
    str = g_string_new(NULL);

    cols = max > 65 ? 1 : (65 / (max+3)); /* "[] " */
    lines = items <= cols ? 1 : items/cols + 1;
    if (lines > items) lines = items;

    last = NULL; linebuf = g_malloc(max+1); linebuf[max] = '\0';
    for (line = 0, col = 0, skip = 1, tmp = nicklist; line < lines; last = rec, tmp = tmp->next)
    {
	rec = tmp->data;

	if (--skip == 0)
	{
      	    char *ret, nickmode[2] = { 0, 0 };
	    skip = lines;
	    memset(linebuf, ' ', max);
	    nickmode[0] = rec->op ? '@' : rec->voice ? '+' : ' ';
	    memcpy(linebuf, rec->nick, strlen(rec->nick));
	    ret = output_format_get_text(MODULE_NAME, NULL,
					 channel->server, channel->name,
					 IRCTXT_NAMES_NICK, nickmode, linebuf);
            g_string_append(str, ret);
	    g_free(ret);
	    cols++;
	}

	if (col == cols || tmp->next == NULL)
	{
	    printtext(channel->server, channel->name, MSGLEVEL_CLIENTCRAP, str->str);
	    g_string_truncate(str, 0);
	    col = 0; line++;
	    tmp = g_slist_nth(nicklist, line-1); skip = 1;
	}
    }
    if (str->len != 0)
	printtext(channel->server, channel->name, MSGLEVEL_CLIENTCRAP, str->str);
    g_string_free(str, TRUE);
    g_free(linebuf);
}

static void display_nicks(CHANNEL_REC *channel)
{
    NICK_REC *nick;
    GSList *tmp, *nicklist, *sorted;
    gint nicks, normal, voices, ops, len, max;

    nicks = normal = voices = ops = 0;
    nicklist = nicklist_getnicks(channel);
    sorted = NULL;

    /* sort the nicklist */
    max = 0;
    for (tmp = nicklist; tmp != NULL; tmp = tmp->next)
    {
	nick = tmp->data;

	sorted = g_slist_insert_sorted(sorted, nick, (GCompareFunc) nicklist_compare);
        if (nick->op)
	    ops++;
	else if (nick->voice)
	    voices++;
	else
	    normal++;
	nicks++;

	len = strlen(nick->nick);
	if (len > max) max = len;
    }
    g_slist_free(nicklist);

    /* display the nicks */
    printformat(channel->server, channel->name, MSGLEVEL_CRAP, IRCTXT_NAMES, channel->name, "");
    display_sorted_nicks(channel, sorted, nicks, max);
    g_slist_free(sorted);

    printformat(channel->server, channel->name, MSGLEVEL_CRAP, IRCTXT_ENDOFNAMES,
		channel->name, nicks, ops, voices, normal);
}

static void event_end_of_names(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;
	IRC_CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL)
		printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_ENDOFNAMES, channel, 0, 0, 0, 0);
	else
		display_nicks(CHANNEL(chanrec));
	g_free(params);
}

static void event_who(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *channel, *user, *host, *stat, *realname, *hops;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 8, NULL, &channel, &user, &host, NULL, &nick, &stat, &realname);

	/* split hops/realname */
	hops = realname;
	while (*realname != '\0' && *realname != ' ') realname++;
	while (*realname == ' ') realname++;
	if (realname > hops) realname[-1] = '\0';

	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHO,
		    channel, nick, stat, hops, user, host, realname);

	g_free(params);
}

static void event_end_of_who(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_END_OF_WHO, channel);
	g_free(params);
}

static void event_ban_list(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *ban, *setby, *tims;
	long secs;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);
	secs = *tims == '\0' ? 0 :
		(long) (time(NULL) - atol(tims));

	printformat(server, NULL, MSGLEVEL_CRAP,
		    *setby == '\0' ? IRCTXT_BANLIST : IRCTXT_BANLIST_LONG,
		    channel, ban, setby, secs);

	g_free(params);
}

static void event_eban_list(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *ban, *setby, *tims;
	long secs;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);
	secs = *tims == '\0' ? 0 :
		(long) (time(NULL) - atol(tims));

	printformat(server, NULL, MSGLEVEL_CRAP,
		    *setby == '\0' ? IRCTXT_EBANLIST : IRCTXT_EBANLIST_LONG,
		    channel, ban, setby, secs);

	g_free(params);
}

static void event_silence_list(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *mask;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &mask);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_SILENCE_LINE, nick, mask);
	g_free(params);
}


static void event_invite_list(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *invite;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &invite);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_INVITELIST, channel, invite);
	g_free(params);
}

static void event_nick_in_use(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	if (server->connected)
		printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NICK_IN_USE, nick);

	g_free(params);
}

static void event_topic_get(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *topic;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &topic);
	printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_TOPIC, channel, topic);
	g_free(params);
}

static void event_topic_info(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *timestr, *channel, *topicby, *topictime;
    glong ltime;
    time_t t;
    struct tm *tim;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 4, NULL, &channel, &topicby, &topictime);

    if (sscanf(topictime, "%lu", &ltime) != 1) ltime = 0; /* topic set date */
    t = (time_t) ltime;
    tim = localtime(&t);
    timestr = g_strdup(asctime(tim));
    if (timestr[strlen(timestr)-1] == '\n') timestr[strlen(timestr)-1] = '\0';

    printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_TOPIC_INFO, topicby, timestr);
    g_free(timestr);
    g_free(params);
}

static void event_channel_mode(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST, NULL, &channel, &mode);
	printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_CHANNEL_MODE, channel, mode);
	g_free(params);
}

static void event_channel_created(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *times, *timestr;
    glong timeval;
    time_t t;
    struct tm *tim;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 3, NULL, &channel, &times);

    if (sscanf(times, "%ld", &timeval) != 1) timeval = 0;
    t = (time_t) timeval;
    tim = localtime(&t);
    timestr = g_strdup(asctime(tim));
    if (timestr[strlen(timestr)-1] == '\n') timestr[strlen(timestr)-1] = '\0';

    printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_CHANNEL_CREATED, channel, timestr);
    g_free(timestr);
    g_free(params);
}

static void event_away(const char *data, IRC_SERVER_REC *server)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_AWAY);
}

static void event_unaway(const char *data, IRC_SERVER_REC *server)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_UNAWAY);
}

static void event_userhost(const char *data, IRC_SERVER_REC *server)
{
	char *params, *hosts;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &hosts);
	printtext(server, NULL, MSGLEVEL_CRAP, "%s", hosts);
	g_free(params);
}

static void event_sent_invite(const char *data, IRC_SERVER_REC *server)
{
        char *params, *nick, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &channel);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_INVITING, nick, channel);
	g_free(params);
}

static void event_whois(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *user, *host, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick, &user, &host, NULL, &realname);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS, nick, user, host, realname);
	g_free(params);
}

static void event_whois_idle(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *secstr, *signonstr, *rest;
	long days, hours, mins, secs;
	time_t signon;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5 | PARAM_FLAG_GETREST, NULL,
				  &nick, &secstr, &signonstr, &rest);

	secs = atol(secstr);
	signon = strstr(rest, "signon time") == NULL ? 0 :
		(time_t) atol(signonstr);

	days = secs/3600/24;
	hours = (secs%(3600*24))/3600;
	mins = (secs%3600)/60;
	secs %= 60;

	if (signon == 0)
		printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_IDLE,
			    nick, days, hours, mins, secs);
	else {
		char *timestr;
		struct tm *tim;

		tim = localtime(&signon);
		timestr = g_strdup(asctime(tim));
		if (timestr[strlen(timestr)-1] == '\n')
			timestr[strlen(timestr)-1] = '\0';
		printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_IDLE_SIGNON,
			    nick, days, hours, mins, secs, timestr);
		g_free(timestr);
	}
	g_free(params);
}

static void event_whois_server(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *whoserver, *desc;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &nick, &whoserver, &desc);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_SERVER, nick, whoserver, desc);
	g_free(params);
}

static void event_whois_oper(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_OPER, nick);
	g_free(params);
}

static void event_whois_registered(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_REGISTERED, nick);
	g_free(params);
}

static void event_whowas(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *user, *host, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick, &user, &host, NULL, &realname);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOWAS, nick, user, host, realname);
	g_free(params);
}

static void event_whois_channels(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *chans;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &chans);

	/* sure - we COULD print the channel names as-is, but since the
	   colors, bolds, etc. are mostly just to fool people, I think we
	   should show the channel names as they REALLY are so they could
	   even be joined without any extra tricks. */
        chans = show_lowascii(chans);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_CHANNELS, nick, chans);
	g_free(chans);

	g_free(params);
}

static void event_whois_away(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	if (server->whois_coming || !settings_get_bool("show_away_once") ||
	    last_away_nick == NULL || g_strcasecmp(last_away_nick, nick) != 0 ||
	    last_away_msg == NULL || g_strcasecmp(last_away_msg, awaymsg) != 0) {
		/* don't show the same away message from the same nick all the time */
		g_free_not_null(last_away_nick);
		g_free_not_null(last_away_msg);
		last_away_nick = g_strdup(nick);
		last_away_msg = g_strdup(awaymsg);

		printformat(server, nick, MSGLEVEL_CRAP, server->whois_coming ?
			    IRCTXT_WHOIS_AWAY : IRCTXT_NICK_AWAY, nick, awaymsg);
	}
	g_free(params);
}

static void event_end_of_whois(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	if (server->whois_found) printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_END_OF_WHOIS, nick);
	g_free(params);
}

static void event_chanserv_url(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *url;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &url);
	printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_CHANNEL_URL, url);
	g_free(params);
}

static void event_end_of_whowas(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	if (server->whowas_found) printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_END_OF_WHOWAS, nick);
	g_free(params);
}

static void event_target_unavailable(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	if (!ischannel(*channel)) {
		/* nick unavailable */
		printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NICK_UNAVAILABLE, channel);
	} else {
		/* channel is unavailable. */
		printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_JOINERROR_UNAVAIL, channel);
	}

	g_free(params);
}

static void event_no_such_nick(const char *data, IRC_SERVER_REC *server)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_NO_SUCH_NICK, nick);
	g_free(params);
}

static void event_no_such_channel(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NO_SUCH_CHANNEL, channel);
	g_free(params);
}

static void cannot_join(const char *data, IRC_SERVER_REC *server, int format)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, NULL, MSGLEVEL_CRAP, format, channel);
	g_free(params);
}

static void event_too_many_channels(const char *data, IRC_SERVER_REC *server)
{
	cannot_join(data, server, IRCTXT_JOINERROR_TOOMANY);
}

static void event_duplicate_channel(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel, *p;

	g_return_if_fail(data != NULL);

	/* this new addition to ircd breaks completely with older
	   "standards", "nick Duplicate ::!!channel ...." */
	params = event_get_params(data, 3, NULL, NULL, &channel);
	p = strchr(channel, ' ');
	if (p != NULL) *p = '\0';

	if (channel[0] == '!' && channel[1] == '!') {
		printformat(server, NULL, MSGLEVEL_CRAP,
			    IRCTXT_JOINERROR_DUPLICATE, channel+1);
	}

	g_free(params);
}

static void event_channel_is_full(const char *data, IRC_SERVER_REC *server)
{
	cannot_join(data, server, IRCTXT_JOINERROR_FULL);
}

static void event_invite_only(const char *data, IRC_SERVER_REC *server)
{
	cannot_join(data, server, IRCTXT_JOINERROR_INVITE);
}

static void event_banned(const char *data, IRC_SERVER_REC *server)
{
	cannot_join(data, server, IRCTXT_JOINERROR_BANNED);
}

static void event_bad_channel_key(const char *data, IRC_SERVER_REC *server)
{
	cannot_join(data, server, IRCTXT_JOINERROR_BAD_KEY);
}

static void event_bad_channel_mask(const char *data, IRC_SERVER_REC *server)
{
	cannot_join(data, server, IRCTXT_JOINERROR_BAD_MASK);
}

static void event_unknown_mode(const char *data, IRC_SERVER_REC *server)
{
	char *params, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &mode);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_UNKNOWN_MODE, mode);
	g_free(params);
}

static void event_not_chanop(const char *data, IRC_SERVER_REC *server)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NOT_CHANOP, channel);
	g_free(params);
}

static void event_received(const char *data, IRC_SERVER_REC *server,
			   const char *nick, const char *addr)
{
	char *params, *args, *ptr;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, NULL, &args);
	ptr = strstr(args, " :");
	if (ptr != NULL) *(ptr+1) = ' ';
	printtext(server, NULL, MSGLEVEL_CRAP, "%s", args);
	g_free(params);
}

static void event_motd(const char *data, IRC_SERVER_REC *server)
{
	/* numeric event. */
	char *params, *args, *ptr;

	/* don't ignore motd anymore after 3 seconds of connection time -
	   we might have called /MOTD */
	if (settings_get_bool("skip_motd") &&
	    time(NULL)-3 <= server->real_connect_time)
		return;

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST, NULL, &args);
	ptr = strstr(args, " :");
	if (ptr != NULL) *(ptr+1) = ' ';
	printtext(server, NULL, MSGLEVEL_CRAP, "%s", args);
	g_free(params);
}

static void sig_empty(void)
{
}

void fe_events_numeric_init(void)
{
	last_away_nick = NULL;
	last_away_msg = NULL;

	signal_add("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_add("event 303", (SIGNAL_FUNC) event_ison);
	signal_add("event 353", (SIGNAL_FUNC) event_names_list);
	signal_add("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_add("event 352", (SIGNAL_FUNC) event_who);
	signal_add("event 315", (SIGNAL_FUNC) event_end_of_who);
	signal_add("event 271", (SIGNAL_FUNC) event_silence_list);
	signal_add("event 272", (SIGNAL_FUNC) sig_empty);
	signal_add("event 367", (SIGNAL_FUNC) event_ban_list);
	signal_add("event 348", (SIGNAL_FUNC) event_eban_list);
	signal_add("event 346", (SIGNAL_FUNC) event_invite_list);
	signal_add("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_add("event 332", (SIGNAL_FUNC) event_topic_get);
	signal_add("event 333", (SIGNAL_FUNC) event_topic_info);
	signal_add("event 324", (SIGNAL_FUNC) event_channel_mode);
	signal_add("event 329", (SIGNAL_FUNC) event_channel_created);
	signal_add("event 306", (SIGNAL_FUNC) event_away);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
	signal_add("event 311", (SIGNAL_FUNC) event_whois);
	signal_add("event 301", (SIGNAL_FUNC) event_whois_away);
	signal_add("event 312", (SIGNAL_FUNC) event_whois_server);
	signal_add("event 313", (SIGNAL_FUNC) event_whois_oper);
	signal_add("event 307", (SIGNAL_FUNC) event_whois_registered);
	signal_add("event 314", (SIGNAL_FUNC) event_whowas);
	signal_add("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_add("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_add("event 328", (SIGNAL_FUNC) event_chanserv_url);
	signal_add("event 369", (SIGNAL_FUNC) event_end_of_whowas);
	signal_add("event 319", (SIGNAL_FUNC) event_whois_channels);
	signal_add("event 302", (SIGNAL_FUNC) event_userhost);
	signal_add("event 341", (SIGNAL_FUNC) event_sent_invite);

	signal_add("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_add("event 401", (SIGNAL_FUNC) event_no_such_nick);
	signal_add("event 403", (SIGNAL_FUNC) event_no_such_channel);
	signal_add("event 405", (SIGNAL_FUNC) event_too_many_channels);
	signal_add("event 407", (SIGNAL_FUNC) event_duplicate_channel);
	signal_add("event 471", (SIGNAL_FUNC) event_channel_is_full);
	signal_add("event 472", (SIGNAL_FUNC) event_unknown_mode);
	signal_add("event 473", (SIGNAL_FUNC) event_invite_only);
	signal_add("event 474", (SIGNAL_FUNC) event_banned);
	signal_add("event 475", (SIGNAL_FUNC) event_bad_channel_key);
	signal_add("event 476", (SIGNAL_FUNC) event_bad_channel_mask);
	signal_add("event 482", (SIGNAL_FUNC) event_not_chanop);
	signal_add("event 375", (SIGNAL_FUNC) event_motd);
	signal_add("event 376", (SIGNAL_FUNC) event_motd);
	signal_add("event 372", (SIGNAL_FUNC) event_motd);
	signal_add("event 422", (SIGNAL_FUNC) event_motd);

	signal_add("event 004", (SIGNAL_FUNC) event_received);
	signal_add("event 364", (SIGNAL_FUNC) event_received);
	signal_add("event 365", (SIGNAL_FUNC) event_received);
	signal_add("event 465", (SIGNAL_FUNC) event_received);
}

void fe_events_numeric_deinit(void)
{
	g_free_not_null(last_away_nick);
	g_free_not_null(last_away_msg);

	signal_remove("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_remove("event 303", (SIGNAL_FUNC) event_ison);
	signal_remove("event 353", (SIGNAL_FUNC) event_names_list);
	signal_remove("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_remove("event 352", (SIGNAL_FUNC) event_who);
	signal_remove("event 315", (SIGNAL_FUNC) event_end_of_who);
	signal_remove("event 271", (SIGNAL_FUNC) event_silence_list);
	signal_remove("event 272", (SIGNAL_FUNC) sig_empty);
	signal_remove("event 367", (SIGNAL_FUNC) event_ban_list);
	signal_remove("event 348", (SIGNAL_FUNC) event_eban_list);
	signal_remove("event 346", (SIGNAL_FUNC) event_invite_list);
	signal_remove("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_remove("event 332", (SIGNAL_FUNC) event_topic_get);
	signal_remove("event 333", (SIGNAL_FUNC) event_topic_info);
	signal_remove("event 324", (SIGNAL_FUNC) event_channel_mode);
	signal_remove("event 329", (SIGNAL_FUNC) event_channel_created);
	signal_remove("event 306", (SIGNAL_FUNC) event_away);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
	signal_remove("event 311", (SIGNAL_FUNC) event_whois);
	signal_remove("event 301", (SIGNAL_FUNC) event_whois_away);
	signal_remove("event 312", (SIGNAL_FUNC) event_whois_server);
	signal_remove("event 313", (SIGNAL_FUNC) event_whois_oper);
	signal_remove("event 307", (SIGNAL_FUNC) event_whois_registered);
	signal_remove("event 314", (SIGNAL_FUNC) event_whowas);
	signal_remove("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_remove("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_remove("event 328", (SIGNAL_FUNC) event_chanserv_url);
	signal_remove("event 369", (SIGNAL_FUNC) event_end_of_whowas);
	signal_remove("event 319", (SIGNAL_FUNC) event_whois_channels);
	signal_remove("event 302", (SIGNAL_FUNC) event_userhost);
	signal_remove("event 341", (SIGNAL_FUNC) event_sent_invite);

	signal_remove("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_remove("event 401", (SIGNAL_FUNC) event_no_such_nick);
	signal_remove("event 403", (SIGNAL_FUNC) event_no_such_channel);
	signal_remove("event 405", (SIGNAL_FUNC) event_too_many_channels);
	signal_remove("event 407", (SIGNAL_FUNC) event_duplicate_channel);
	signal_remove("event 471", (SIGNAL_FUNC) event_channel_is_full);
	signal_remove("event 472", (SIGNAL_FUNC) event_unknown_mode);
	signal_remove("event 473", (SIGNAL_FUNC) event_invite_only);
	signal_remove("event 474", (SIGNAL_FUNC) event_banned);
	signal_remove("event 475", (SIGNAL_FUNC) event_bad_channel_key);
	signal_remove("event 476", (SIGNAL_FUNC) event_bad_channel_mask);
	signal_remove("event 482", (SIGNAL_FUNC) event_not_chanop);
	signal_remove("event 375", (SIGNAL_FUNC) event_motd);
	signal_remove("event 376", (SIGNAL_FUNC) event_motd);
	signal_remove("event 372", (SIGNAL_FUNC) event_motd);
	signal_remove("event 422", (SIGNAL_FUNC) event_motd);

	signal_remove("event 004", (SIGNAL_FUNC) event_received);
	signal_remove("event 364", (SIGNAL_FUNC) event_received);
	signal_remove("event 365", (SIGNAL_FUNC) event_received);
	signal_remove("event 465", (SIGNAL_FUNC) event_received);
}
