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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/fe-common/irc/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/recode.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/core/nicklist.h>
#include <irssi/src/irc/core/mode-lists.h>

#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/fe-channels.h>
#include <irssi/src/fe-common/irc/fe-irc-server.h>
#include <irssi/src/fe-common/irc/fe-irc-channels.h>

static void print_event_received(IRC_SERVER_REC *server, const char *data,
				 const char *nick, int target_param);

static char *last_away_nick = NULL;
static char *last_away_msg = NULL;

static void event_user_mode(IRC_SERVER_REC *server, const char *data)
{
	char *params, *mode;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &mode);
        printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_USER_MODE,
                    g_strchomp(mode));
	g_free(params);
}

static void event_ison(IRC_SERVER_REC *server, const char *data)
{
	char *params, *online;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2, NULL, &online);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_ONLINE, online);
	g_free(params);
}

static void event_names_list(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel, *names;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, NULL, &channel, &names);

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL || chanrec->names_got) {
		printformat_module("fe-common/core", server, channel,
				   MSGLEVEL_CRAP, TXT_NAMES,
				   channel, 0, 0, 0, 0, 0);
                printtext(server, channel, MSGLEVEL_CRAP, "%s", names);

	}
	g_free(params);
}

static void event_end_of_names(IRC_SERVER_REC *server, const char *data,
			       const char *nick)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL || chanrec->names_got)
		print_event_received(server, data, nick, FALSE);
	g_free(params);
}

static void event_who(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *channel, *user, *host, *stat, *realname, *hops;
	char *serv, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 8, NULL, &channel, &user,
				  &host, &serv, &nick, &stat, &realname);

	/* split hops/realname */
	hops = realname;
	while (*realname != '\0' && *realname != ' ') realname++;
	if (*realname == ' ')
		*realname++ = '\0';

	recoded = recode_in(SERVER(server), realname, nick);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHO,
		    channel, nick, stat, hops, user, host, recoded, serv);

	g_free(params);
	g_free(recoded);
}

static void event_end_of_who(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_END_OF_WHO, channel);
	g_free(params);
}

static void event_ban_list(IRC_SERVER_REC *server, const char *data)
{
	IRC_CHANNEL_REC *chanrec;
	BAN_REC *banrec;
	const char *channel;
	char *params, *ban, *setby, *tims, *timestr, *ago;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel,
				  &ban, &setby, &tims);
	timestr = my_asctime((time_t) atoll(tims));
	ago = time_ago((time_t) atoll(tims));

	chanrec = irc_channel_find(server, channel);
	banrec = chanrec == NULL ? NULL : banlist_find(chanrec->banlist, ban);

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
	            *setby == '\0' ? IRCTXT_BANLIST : IRCTXT_BANLIST_LONG,
	            banrec == NULL ? 0 : g_slist_index(chanrec->banlist, banrec) + 1, channel, ban,
	            setby, ago, timestr);

	g_free(timestr);
	g_free(params);
}

static void event_eban_list(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *ban, *setby, *tims, *timestr, *ago;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel,
				  &ban, &setby, &tims);
	timestr = my_asctime((time_t) atoll(tims));
	ago = time_ago((time_t) atoll(tims));

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
	            *setby == '\0' ? IRCTXT_EBANLIST : IRCTXT_EBANLIST_LONG, channel, ban, setby,
	            timestr, ago);

	g_free(timestr);
	g_free(params);
}

static void do_quiet_list(IRC_SERVER_REC *server, const char *channel, char *ban, char *setby,
                          char *tims)
{
	char *timestr, *ago;

	timestr = my_asctime((time_t) atoll(tims));
	ago = time_ago((time_t) atoll(tims));

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
	            *setby == '\0' ? IRCTXT_QUIETLIST : IRCTXT_QUIETLIST_LONG, channel, ban, setby,
	            ago, timestr);

	g_free(timestr);
}

static void event_quiet_list(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *ban, *setby, *tims;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &channel, NULL, &ban, &setby, &tims);
	do_quiet_list(server, channel, ban, setby, tims);

	g_free(params);
}

static void event_silence_list(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *mask;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &mask);
	printformat(server, NULL, MSGLEVEL_CRAP,
		    IRCTXT_SILENCE_LINE, nick, mask);
	g_free(params);
}

static void event_accept_list(IRC_SERVER_REC *server, const char *data)
{
	char *params, *accepted;

	g_return_if_fail(data != NULL);
	g_return_if_fail(server != NULL);

	params = event_get_params(data, 2 | PARAM_FLAG_GETREST,
			NULL, &accepted);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_ACCEPT_LIST, accepted);
	g_free(params);
}

static void event_invite_list(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *invite, *setby, *tims, *timestr, *ago;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &invite,
			&setby, &tims);
	timestr = my_asctime((time_t) atoll(tims));
	ago = time_ago((time_t) atoll(tims));

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
	            *setby == '\0' ? IRCTXT_INVITELIST : IRCTXT_INVITELIST_LONG, channel, invite,
	            setby, timestr, ago);

	g_free(timestr);
	g_free(params);
}

static void event_nick_in_use(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	if (server->connected) {
		printformat(server, NULL, MSGLEVEL_CRAP,
			    IRCTXT_NICK_IN_USE, nick);
	}

	g_free(params);
}

static void event_topic_get(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *topic, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &topic);
	recoded = recode_in(SERVER(server), topic, channel);
	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_TOPIC, channel, recoded);
	g_free(params);
	g_free(recoded);
}

static void event_topic_info(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *timestr, *bynick, *byhost, *topictime;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &channel,
				  &bynick, &topictime);

        timestr = my_asctime((time_t) atol(topictime));

	byhost = strchr(bynick, '!');
	if (byhost != NULL)
		*byhost++ = '\0';

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP, IRCTXT_TOPIC_INFO,
		    bynick, timestr, byhost == NULL ? "" : byhost);
	g_free(timestr);
	g_free(params);
}

static void event_channel_mode(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3 | PARAM_FLAG_GETREST,
				  NULL, &channel, &mode);
	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_CHANNEL_MODE, channel, g_strchomp(mode));
	g_free(params);
}

static void event_channel_created(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *createtime, *timestr;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &createtime);

        timestr = my_asctime((time_t) atol(createtime));
	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_CHANNEL_CREATED, channel, timestr);
	g_free(timestr);
	g_free(params);
}

static void event_nowaway(IRC_SERVER_REC *server, const char *data)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_AWAY);
}

static void event_unaway(IRC_SERVER_REC *server, const char *data)
{
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_UNAWAY);
}

static void event_away(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *awaymsg, *recoded;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	recoded = recode_in(SERVER(server), awaymsg, nick);
	if (!settings_get_bool("show_away_once") ||
	    last_away_nick == NULL ||
	    g_ascii_strcasecmp(last_away_nick, nick) != 0 ||
	    last_away_msg == NULL ||
	    g_ascii_strcasecmp(last_away_msg, awaymsg) != 0) {
		/* don't show the same away message
		   from the same nick all the time */
		g_free_not_null(last_away_nick);
		g_free_not_null(last_away_msg);
		last_away_nick = g_strdup(nick);
		last_away_msg = g_strdup(awaymsg);

		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_NICK_AWAY, nick, recoded);
	}
	g_free(params);
	g_free(recoded);
}

static void event_userhost(IRC_SERVER_REC *server, const char *data)
{
	char *params, *hosts;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &hosts);
	printtext(server, NULL, MSGLEVEL_CRAP, "%s", hosts);
	g_free(params);
}

static void event_sent_invite(IRC_SERVER_REC *server, const char *data)
{
        char *params, *nick, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &channel);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_INVITING, nick, channel);
	g_free(params);
}

static void event_chanserv_url(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *url;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &url);
	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_CHANNEL_URL, channel, url);
	g_free(params);
}

static void event_target_unavailable(IRC_SERVER_REC *server, const char *data,
				     const char *nick, const char *addr)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *target;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &target);
	if (!server_ischannel(SERVER(server), target)) {
		/* nick unavailable */
		printformat(server, NULL, MSGLEVEL_CRAP,
			    IRCTXT_NICK_UNAVAILABLE, target);
	} else {
		chanrec = irc_channel_find(server, target);
		if (chanrec != NULL && chanrec->joined) {
			/* dalnet - can't change nick while being banned */
			print_event_received(server, data, nick, FALSE);
		} else {
			/* channel is unavailable. */
			printformat(server, NULL, MSGLEVEL_CRAP,
				    IRCTXT_JOINERROR_UNAVAIL, target);
		}
	}

	g_free(params);
}

static void event_no_such_nick(IRC_SERVER_REC *server, const char *data,
				     const char *nick, const char *addr)
{
	char *params, *unick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &unick);
	if (!g_strcmp0(unick, "*"))
		/* more information will be in the description,
		 * e.g. * :Target left IRC. Failed to deliver: [hi] */
		print_event_received(server, data, nick, FALSE);
	else
		printformat(server, unick, MSGLEVEL_CRAP, IRCTXT_NO_SUCH_NICK, unick);
	g_free(params);
}

static void event_no_such_channel(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_NO_SUCH_CHANNEL, channel);
	g_free(params);
}

static void cannot_join(IRC_SERVER_REC *server, const char *data, int format)
{
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	printformat(server, NULL, MSGLEVEL_CRAP, format, channel);
	g_free(params);
}

static void event_too_many_channels(IRC_SERVER_REC *server, const char *data)
{
	cannot_join(server, data, IRCTXT_JOINERROR_TOOMANY);
}

static void event_duplicate_channel(IRC_SERVER_REC *server, const char *data,
		const char *nick)
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
	} else
		print_event_received(server, data, nick, FALSE);

	g_free(params);
}

static void event_channel_is_full(IRC_SERVER_REC *server, const char *data)
{
	cannot_join(server, data, IRCTXT_JOINERROR_FULL);
}

static void event_invite_only(IRC_SERVER_REC *server, const char *data)
{
	cannot_join(server, data, IRCTXT_JOINERROR_INVITE);
}

static void event_banned(IRC_SERVER_REC *server, const char *data)
{
	cannot_join(server, data, IRCTXT_JOINERROR_BANNED);
}

static void event_bad_channel_key(IRC_SERVER_REC *server, const char *data)
{
	cannot_join(server, data, IRCTXT_JOINERROR_BAD_KEY);
}

static void event_bad_channel_mask(IRC_SERVER_REC *server, const char *data)
{
	cannot_join(server, data, IRCTXT_JOINERROR_BAD_MASK);
}

static void event_477(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	/* Numeric 477 can mean many things:
	 * modeless channel, cannot join/send to channel (+r/+R/+M).
	 * If we tried to join this channel, display the error in the
	 * status window. Otherwise display it in the channel window.
	 */
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = irc_channel_find(server, channel);
	print_event_received(server, data, nick, chanrec == NULL || chanrec->joined);
	g_free(params);
}

static void event_489(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	/* Numeric 489 can mean one of two things things:
	 * cannot join to channel (secure only), or not chanop or voice.
	 * If we tried to join this channel, display the joinerror.
	 * Otherwise depending on the channel being joined or not
	 * display the error in the channel or status window.
	 */
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = irc_channel_find(server, channel);
	if (chanrec != NULL && !chanrec->joined) {
		cannot_join(server, data, IRCTXT_JOINERROR_SECURE_ONLY);
	} else {
		print_event_received(server, data, nick, chanrec == NULL || chanrec->joined);
	}
	g_free(params);
}

static void event_help(IRC_SERVER_REC *server, int formatnum, const char *data)
{
	/* Common handling for umerics 704 (RPL_HELPSTART), 705 (RPL_HELPTXT),
	 * and 706 (RPL_ENDOFHELP); sent as a reply to HELP or HELPOP command.
	 */
	char *params, *topic, *help_text;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &topic, &help_text);

	g_return_if_fail(help_text != NULL);

	if (help_text[0] == '\0') {
		/* Empty lines can be used by servers for styling; and we need to replace
		 * them with something non-empty or they would be dropped when displayed.
		 */
		help_text = " ";
	}

	printformat(server, NULL, MSGLEVEL_CRAP, formatnum, topic, help_text);
	g_free(params);
}

static void event_helpstart(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	/* Numeric 704 (RPL_HELPSTART) sent as a reply to HELP or HELPOP command.
	 */
	event_help(server, IRCTXT_SERVER_HELP_START, data);
}

static void event_helptxt(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	/* Numeric 705 (RPL_HELPTXT), sent as a reply to HELP or HELPOP command.
	 */
	event_help(server, IRCTXT_SERVER_HELP_TXT, data);
}

static void event_endofhelp(IRC_SERVER_REC *server, const char *data, const char *nick)
{
	/* Numeric 706 (RPL_ENDOFHELP), sent as a reply to HELP or HELPOP command.
	 */
	event_help(server, IRCTXT_SERVER_END_OF_HELP, data);
}

static void event_target_too_fast(IRC_SERVER_REC *server, const char *data,
		      const char *nick)
{
	/* Target change too fast, could be nick or channel.
	 * If we tried to join this channel, display the error in the
	 * status window. Otherwise display it in the channel window.
	 */
	IRC_CHANNEL_REC *chanrec;
	char *params, *channel;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);

	chanrec = irc_channel_find(server, channel);
	print_event_received(server, data, nick, chanrec == NULL || chanrec->joined);
	g_free(params);
}

static void event_unknown_mode(IRC_SERVER_REC *server, const char *data)
{
	char *params, *mode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &mode);
	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_UNKNOWN_MODE, mode);
	g_free(params);
}

static void event_numeric(IRC_SERVER_REC *server, const char *data,
			  const char *nick)
{
	data = strchr(data, ' ');
	if (data != NULL)
                print_event_received(server, data+1, nick, FALSE);
}

static void print_event_received(IRC_SERVER_REC *server, const char *data,
				 const char *nick, int target_param)
{
	char *target, *args, *ptr, *ptr2, *recoded;
	int format;

	g_return_if_fail(data != NULL);

        /* first param is our nick, "*" or a channel */
	ptr = strchr(data, ' ');
	if (ptr == NULL)
		return;
	ptr++;

	if (server_ischannel(SERVER(server), data)) /* directed at channel */
		target = g_strndup(data, (int)(ptr - data - 1));
	else if (!target_param || *ptr == ':' || (ptr2 = strchr(ptr, ' ')) == NULL)
		target = NULL;
	else {
                /* target parameter expected and present */
                target = g_strndup(ptr, (int) (ptr2-ptr));
	}

	/* param1 param2 ... :last parameter */
	if (*ptr == ':') {
                /* only one parameter */
		args = g_strdup(ptr+1);
	} else {
		args = g_strdup(ptr);
		ptr = strstr(args, " :");
		if (ptr != NULL)
			memmove(ptr+1, ptr+2, strlen(ptr+1));
	}

	recoded = recode_in(SERVER(server), args, NULL);
	format = nick == NULL || server->real_address == NULL ||
		g_strcmp0(nick, server->real_address) == 0 ?
		IRCTXT_DEFAULT_EVENT : IRCTXT_DEFAULT_EVENT_SERVER;
	printformat(server, target, MSGLEVEL_CRAP, format,
		    nick, recoded, current_server_event);

	g_free(recoded);
	g_free(args);
	g_free(target);
}

static void event_received(IRC_SERVER_REC *server, const char *data,
			   const char *nick)
{
        print_event_received(server, data, nick, FALSE);
}

static void event_target_received(IRC_SERVER_REC *server, const char *data,
				  const char *nick)
{
        print_event_received(server, data, nick, TRUE);
}

static void event_hybrid_quiet_list(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *ban, *setby, *tims;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel, &ban, &setby, &tims);

	if (*tims == '\0') {
		/* probably not a quiet list */
		event_target_received(server, data, NULL);
		return;
	}

	do_quiet_list(server, channel, ban, setby, tims);

	g_free(params);
}

static void event_motd(IRC_SERVER_REC *server, const char *data,
		       const char *nick, const char *addr)
{
	/* don't ignore motd anymore after 3 seconds of connection time -
	   we might have called /MOTD */
	if (settings_get_bool("skip_motd") && !server->motd_got)
		return;

        print_event_received(server, data, nick, FALSE);
}

static void sig_empty(void)
{
}

void fe_events_numeric_init(void)
{
	last_away_nick = NULL;
	last_away_msg = NULL;

	/* clang-format off */
	signal_add("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_add("event 303", (SIGNAL_FUNC) event_ison);
	signal_add("event 353", (SIGNAL_FUNC) event_names_list);
	signal_add_first("event 366", (SIGNAL_FUNC) event_end_of_names);
	signal_add("event 352", (SIGNAL_FUNC) event_who);
	signal_add("event 315", (SIGNAL_FUNC) event_end_of_who);
	signal_add("event 271", (SIGNAL_FUNC) event_silence_list);
	signal_add("event 272", (SIGNAL_FUNC) sig_empty);
	signal_add("event 281", (SIGNAL_FUNC) event_accept_list);
	signal_add("event 367", (SIGNAL_FUNC) event_ban_list);
	signal_add("event 348", (SIGNAL_FUNC) event_eban_list);
	signal_add("event 728", (SIGNAL_FUNC) event_quiet_list);
	signal_add("event 344", (SIGNAL_FUNC) event_hybrid_quiet_list); /* used by ircd-hybrid */
	signal_add("event 346", (SIGNAL_FUNC) event_invite_list);
	signal_add("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_add("event 332", (SIGNAL_FUNC) event_topic_get);
	signal_add("event 333", (SIGNAL_FUNC) event_topic_info);
	signal_add("event 324", (SIGNAL_FUNC) event_channel_mode);
	signal_add("event 329", (SIGNAL_FUNC) event_channel_created);
	signal_add("event 306", (SIGNAL_FUNC) event_nowaway);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
	signal_add("event 301", (SIGNAL_FUNC) event_away);
	signal_add("event 328", (SIGNAL_FUNC) event_chanserv_url);
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
	signal_add("event 477", (SIGNAL_FUNC) event_477);
	signal_add("event 489", (SIGNAL_FUNC) event_489); /* cannot join to channel (secure only), or not chanop or voice. */
	signal_add("event 375", (SIGNAL_FUNC) event_motd);
	signal_add("event 376", (SIGNAL_FUNC) event_motd);
	signal_add("event 372", (SIGNAL_FUNC) event_motd);
	signal_add("event 422", (SIGNAL_FUNC) event_motd);
	signal_add("event 439", (SIGNAL_FUNC) event_target_too_fast);
	signal_add("event 704", (SIGNAL_FUNC) event_helpstart);
	signal_add("event 705", (SIGNAL_FUNC) event_helptxt);
	signal_add("event 706", (SIGNAL_FUNC) event_endofhelp);
	signal_add("event 707", (SIGNAL_FUNC) event_target_too_fast);

        signal_add("default event numeric", (SIGNAL_FUNC) event_numeric);
	/* Because default event numeric only fires if there is no specific
	 * event, add all numerics with a handler elsewhere in irssi that
	 * should not be printed specially here.
	 */
	signal_add("event 001", (SIGNAL_FUNC) event_received);
	signal_add("event 004", (SIGNAL_FUNC) event_received);
	signal_add("event 005", (SIGNAL_FUNC) event_received);
	signal_add("event 254", (SIGNAL_FUNC) event_received);
	signal_add("event 354", (SIGNAL_FUNC) event_received);
	signal_add("event 364", (SIGNAL_FUNC) event_received);
	signal_add("event 365", (SIGNAL_FUNC) event_received);
	signal_add("event 381", (SIGNAL_FUNC) event_received);
	signal_add("event 396", (SIGNAL_FUNC) event_received);
	signal_add("event 421", (SIGNAL_FUNC) event_received);
	signal_add("event 432", (SIGNAL_FUNC) event_received);
	signal_add("event 436", (SIGNAL_FUNC) event_received);
	signal_add("event 438", (SIGNAL_FUNC) event_received);
	signal_add("event 465", (SIGNAL_FUNC) event_received);
	signal_add("event 470", (SIGNAL_FUNC) event_received);
	signal_add("event 479", (SIGNAL_FUNC) event_received);

	signal_add("event 345", (SIGNAL_FUNC) event_target_received); /* end of reop list/hybrid quiet list */
	signal_add("event 347", (SIGNAL_FUNC) event_target_received); /* end of invite exception list */
	signal_add("event 349", (SIGNAL_FUNC) event_target_received); /* end of ban exception list */
	signal_add("event 368", (SIGNAL_FUNC) event_target_received); /* end of ban list */
	signal_add("event 386", (SIGNAL_FUNC) event_target_received); /* owner list; old rsa challenge (harmless) */
	signal_add("event 387", (SIGNAL_FUNC) event_target_received); /* end of owner list */
	signal_add("event 388", (SIGNAL_FUNC) event_target_received); /* protect list */
	signal_add("event 389", (SIGNAL_FUNC) event_target_received); /* end of protect list */
	signal_add("event 404", (SIGNAL_FUNC) event_target_received); /* cannot send to channel */
	signal_add("event 408", (SIGNAL_FUNC) event_target_received); /* cannot send (+c) */
	signal_add("event 442", (SIGNAL_FUNC) event_target_received); /* you're not on that channel */
	signal_add("event 478", (SIGNAL_FUNC) event_target_received); /* ban list is full */
	signal_add("event 482", (SIGNAL_FUNC) event_target_received); /* not chanop */
	signal_add("event 486", (SIGNAL_FUNC) event_target_received); /* cannot /msg (+R) */
	signal_add("event 494", (SIGNAL_FUNC) event_target_received); /* cannot /msg (own +R) */
	signal_add("event 506", (SIGNAL_FUNC) event_target_received); /* cannot send (+R) */
	signal_add("event 716", (SIGNAL_FUNC) event_target_received); /* cannot /msg (+g) */
	signal_add("event 717", (SIGNAL_FUNC) event_target_received); /* +g notified */
	signal_add("event 729", (SIGNAL_FUNC) event_target_received); /* end of quiet (or other) list */
	/* clang-format on */
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
	signal_remove("event 281", (SIGNAL_FUNC) event_accept_list);
	signal_remove("event 367", (SIGNAL_FUNC) event_ban_list);
	signal_remove("event 348", (SIGNAL_FUNC) event_eban_list);
	signal_remove("event 728", (SIGNAL_FUNC) event_quiet_list);
	signal_remove("event 344", (SIGNAL_FUNC) event_hybrid_quiet_list);
	signal_remove("event 346", (SIGNAL_FUNC) event_invite_list);
	signal_remove("event 433", (SIGNAL_FUNC) event_nick_in_use);
	signal_remove("event 332", (SIGNAL_FUNC) event_topic_get);
	signal_remove("event 333", (SIGNAL_FUNC) event_topic_info);
	signal_remove("event 324", (SIGNAL_FUNC) event_channel_mode);
	signal_remove("event 329", (SIGNAL_FUNC) event_channel_created);
	signal_remove("event 306", (SIGNAL_FUNC) event_nowaway);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
	signal_remove("event 301", (SIGNAL_FUNC) event_away);
	signal_remove("event 328", (SIGNAL_FUNC) event_chanserv_url);
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
	signal_remove("event 477", (SIGNAL_FUNC) event_477);
	signal_remove("event 489", (SIGNAL_FUNC) event_489);
	signal_remove("event 375", (SIGNAL_FUNC) event_motd);
	signal_remove("event 376", (SIGNAL_FUNC) event_motd);
	signal_remove("event 372", (SIGNAL_FUNC) event_motd);
	signal_remove("event 422", (SIGNAL_FUNC) event_motd);
	signal_remove("event 439", (SIGNAL_FUNC) event_target_too_fast);
	signal_remove("event 704", (SIGNAL_FUNC) event_helpstart);
	signal_remove("event 705", (SIGNAL_FUNC) event_helptxt);
	signal_remove("event 706", (SIGNAL_FUNC) event_endofhelp);
	signal_remove("event 707", (SIGNAL_FUNC) event_target_too_fast);

        signal_remove("default event numeric", (SIGNAL_FUNC) event_numeric);
	signal_remove("event 001", (SIGNAL_FUNC) event_received);
	signal_remove("event 004", (SIGNAL_FUNC) event_received);
	signal_remove("event 005", (SIGNAL_FUNC) event_received);
	signal_remove("event 254", (SIGNAL_FUNC) event_received);
	signal_remove("event 354", (SIGNAL_FUNC) event_received);
	signal_remove("event 364", (SIGNAL_FUNC) event_received);
	signal_remove("event 365", (SIGNAL_FUNC) event_received);
	signal_remove("event 381", (SIGNAL_FUNC) event_received);
	signal_remove("event 396", (SIGNAL_FUNC) event_received);
	signal_remove("event 421", (SIGNAL_FUNC) event_received);
	signal_remove("event 432", (SIGNAL_FUNC) event_received);
	signal_remove("event 436", (SIGNAL_FUNC) event_received);
	signal_remove("event 438", (SIGNAL_FUNC) event_received);
	signal_remove("event 465", (SIGNAL_FUNC) event_received);
	signal_remove("event 470", (SIGNAL_FUNC) event_received);
	signal_remove("event 479", (SIGNAL_FUNC) event_received);

	signal_remove("event 345", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 347", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 349", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 368", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 386", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 387", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 388", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 389", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 404", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 408", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 442", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 478", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 482", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 486", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 494", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 506", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 716", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 717", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 729", (SIGNAL_FUNC) event_target_received);
}
