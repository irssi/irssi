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
#include "settings.h"

#include "irc.h"
#include "levels.h"
#include "server.h"
#include "channels.h"
#include "nicklist.h"

static char *last_away_nick = NULL;
static char *last_away_msg = NULL;

static void event_user_mode(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *mode;

    g_return_if_fail(data != NULL);
    g_return_if_fail(server != NULL);

    params = event_get_params(data, 2, NULL, &mode);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_USER_MODE, mode);
    g_free(params);
}

static void event_ison(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *online;

    g_return_if_fail(data != NULL);
    g_return_if_fail(server != NULL);

    params = event_get_params(data, 2, NULL, &online);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_ONLINE, online);
    g_free(params);
}

static void event_names_list(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *names;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 4, NULL, NULL, &channel, &names);
    if (channel_find(server, channel) == NULL)
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
    lines = items <= cols ? 1 : items / cols+1;

    last = NULL; linebuf = g_malloc(max+1); linebuf[max] = '\0';
    for (line = 0, col = 0, skip = 1, tmp = nicklist; line < lines; last = rec, tmp = tmp->next)
    {
	rec = tmp->data;

	if (--skip == 0)
	{
	    skip = lines;
	    memset(linebuf, ' ', max);
	    linebuf[0] = rec->op ? '@' : rec->voice ? '+' : ' ';
	    memcpy(linebuf+1, rec->nick, strlen(rec->nick));
	    g_string_sprintfa(str, "%%K[%%n%%_%c%%_%s%%K] ", linebuf[0], linebuf+1);
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

static void event_end_of_names(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel;
    CHANNEL_REC *chanrec;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &channel);

    chanrec = channel_find(server, channel);
    if (chanrec == NULL)
        printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_ENDOFNAMES, channel, 0, 0, 0, 0);
    else
	display_nicks(chanrec);
    g_free(params);
}

static void event_who(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick, *channel, *user, *host, *stat, *realname, *hops;

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

static void event_end_of_who(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &channel);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_END_OF_WHO, channel);
    g_free(params);
}

static void event_ban_list(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *ban, *setby, *tims;
    glong secs, tim;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);

    if (sscanf(tims, "%ld", &tim) != 1) tim = (glong) time(NULL);
    secs = (glong) time(NULL)-tim;

    printformat(server, channel, MSGLEVEL_CRAP,
		*setby == '\0' ? IRCTXT_BANLIST : IRCTXT_BANLIST_LONG,
		channel, ban, setby, secs);

    g_free(params);
}

static void event_eban_list(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *ban, *setby, *tims;
    glong secs, tim;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);

    if (sscanf(tims, "%ld", &tim) != 1) tim = (glong) time(NULL);
    secs = (glong) time(NULL)-tim;

    printformat(server, channel, MSGLEVEL_CRAP,
		*setby == '\0' ? IRCTXT_EBANLIST : IRCTXT_EBANLIST_LONG,
		channel, ban, setby, secs);

    g_free(params);
}

static void event_invite_list(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *invite;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 3, NULL, &channel, &invite);
    printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_INVITELIST, channel, invite);
    g_free(params);
}

static void event_nick_in_use(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &nick);
    if (server->connected)
        printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NICK_IN_USE, nick);

    g_free(params);
}

static void event_topic_get(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *topic;

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

static void event_channel_mode(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel, *mode;

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

static void event_away(gchar *data, IRC_SERVER_REC *server)
{
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_AWAY);
}

static void event_unaway(gchar *data, IRC_SERVER_REC *server)
{
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_UNAWAY);
}

static void event_userhost(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *hosts;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &hosts);
    printtext(server, NULL, MSGLEVEL_CRAP, "%s", hosts);
    g_free(params);
}

static void event_whois(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick, *user, *host, *realname;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 6, NULL, &nick, &user, &host, NULL, &realname);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS, nick, user, host, realname);
    g_free(params);
}

static void event_whois_idle(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick, *secstr, *signon, *rest;
    glong secs, lsignon;
    gint h, m, s;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 5 | PARAM_FLAG_GETREST, NULL, &nick, &secstr, &signon, &rest);
    if (sscanf(secstr, "%ld", &secs) == 0) secs = 0;
    lsignon = 0;
    if (strstr(rest, ", signon time") != NULL)
        sscanf(signon, "%ld", &lsignon);

    h = secs/3600; m = (secs%3600)/60; s = secs%60;
    if (lsignon == 0)
        printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_IDLE, nick, h, m, s);
    else
    {
        gchar *timestr;
	struct tm *tim;
	time_t t;

	t = (time_t) lsignon;
        tim = localtime(&t);
        timestr = g_strdup(asctime(tim));
        if (timestr[strlen(timestr)-1] == '\n') timestr[strlen(timestr)-1] = '\0';
        printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_IDLE_SIGNON, nick, h, m, s, timestr);
        g_free(timestr);
    }
    g_free(params);
}

static void event_whois_server(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick, *whoserver, *desc;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 4, NULL, &nick, &whoserver, &desc);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_SERVER, nick, whoserver, desc);
    g_free(params);
}

static void event_whois_oper(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &nick);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_OPER, nick);
    g_free(params);
}

static void event_whois_channels(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick, *chans;
    GString *str;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 3, NULL, &nick, &chans);

    str = g_string_new(NULL);
    for (; *chans != '\0'; chans++)
    {
	if ((unsigned char) *chans >= 32)
	    g_string_append_c(str, *chans);
	else
	{
	    g_string_append_c(str, '^');
	    g_string_append_c(str, *chans+'A'-1);
	}
    }

    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHOIS_CHANNELS, nick, str->str);
    g_free(params);
    g_string_free(str, TRUE);
}

static void event_whois_away(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick, *awaymsg;

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

	    printformat(server, NULL, MSGLEVEL_CRAP, server->whois_coming ?
			IRCTXT_WHOIS_AWAY : IRCTXT_NICK_AWAY, nick, awaymsg);
    }
    g_free(params);
}

static void event_end_of_whois(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &nick);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_END_OF_WHOIS, nick);
    g_free(params);
}

static void event_target_unavailable(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &channel);
    if (!ischannel(*channel))
    {
        /* nick unavailable */
        printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NICK_UNAVAILABLE, channel);
    }
    else
    {
        /* channel is unavailable. */
        printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_JOINERROR_UNAVAIL, channel);
    }

    g_free(params);
}

static void event_no_such_nick(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &nick);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NO_SUCH_NICK, nick);
    g_free(params);
}

static void event_no_such_channel(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &channel);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NO_SUCH_CHANNEL, channel);
    g_free(params);
}

static void cannot_join(gchar *data, IRC_SERVER_REC *server, gint format)
{
    gchar *params, *channel;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &channel);
    printformat(server, NULL, MSGLEVEL_CRAP, format, channel);
    g_free(params);
}

static void event_too_many_channels(gchar *data, IRC_SERVER_REC *server)
{
    cannot_join(data, server, IRCTXT_JOINERROR_TOOMANY);
}

static void event_channel_is_full(gchar *data, IRC_SERVER_REC *server)
{
    cannot_join(data, server, IRCTXT_JOINERROR_FULL);
}

static void event_invite_only(gchar *data, IRC_SERVER_REC *server)
{
    cannot_join(data, server, IRCTXT_JOINERROR_INVITE);
}

static void event_banned(gchar *data, IRC_SERVER_REC *server)
{
    cannot_join(data, server, IRCTXT_JOINERROR_BANNED);
}

static void event_bad_channel_key(gchar *data, IRC_SERVER_REC *server)
{
    cannot_join(data, server, IRCTXT_JOINERROR_BAD_KEY);
}

static void event_bad_channel_mask(gchar *data, IRC_SERVER_REC *server)
{
    cannot_join(data, server, IRCTXT_JOINERROR_BAD_MASK);
}

static void event_unknown_mode(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *mode;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &mode);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_UNKNOWN_MODE, mode);
    g_free(params);
}

static void event_not_chanop(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *channel;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &channel);
    printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_NOT_CHANOP, channel);
    g_free(params);
}

static void event_received(gchar *data, IRC_SERVER_REC *server, gchar *nick, gchar *addr)
{
    gchar *params, *args, *ptr;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2 | PARAM_FLAG_GETREST, NULL, &args);
    ptr = strstr(args, " :");
    if (ptr != NULL) *(ptr+1) = ' ';
    printtext(server, NULL, MSGLEVEL_CRAP, "%s", args);
    g_free(params);
}

static void event_motd(gchar *data, SERVER_REC *server, gchar *nick, gchar *addr)
{
    /* numeric event. */
    gchar *params, *args, *ptr;

    if (settings_get_bool("toggle_skip_motd"))
	return;

    params = event_get_params(data, 2 | PARAM_FLAG_GETREST, NULL, &args);
    ptr = strstr(args, " :");
    if (ptr != NULL) *(ptr+1) = ' ';
    printtext(server, NULL, MSGLEVEL_CRAP, "%s", args);
    g_free(params);
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
	signal_add("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_add("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_add("event 319", (SIGNAL_FUNC) event_whois_channels);
	signal_add("event 302", (SIGNAL_FUNC) event_userhost);

	signal_add("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_add("event 401", (SIGNAL_FUNC) event_no_such_nick);
	signal_add("event 403", (SIGNAL_FUNC) event_no_such_channel);
	signal_add("event 405", (SIGNAL_FUNC) event_too_many_channels);
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

	signal_add("event 004", (SIGNAL_FUNC) event_received);
	signal_add("event 364", (SIGNAL_FUNC) event_received);
	signal_add("event 365", (SIGNAL_FUNC) event_received);
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
	signal_remove("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_remove("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_remove("event 319", (SIGNAL_FUNC) event_whois_channels);
	signal_remove("event 302", (SIGNAL_FUNC) event_userhost);

	signal_remove("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_remove("event 401", (SIGNAL_FUNC) event_no_such_nick);
	signal_remove("event 403", (SIGNAL_FUNC) event_no_such_channel);
	signal_remove("event 405", (SIGNAL_FUNC) event_too_many_channels);
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

	signal_remove("event 004", (SIGNAL_FUNC) event_received);
	signal_remove("event 364", (SIGNAL_FUNC) event_received);
	signal_remove("event 365", (SIGNAL_FUNC) event_received);
}
