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
#include "levels.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "nicklist.h"
#include "mode-lists.h"

#include "../core/module-formats.h"
#include "printtext.h"
#include "fe-channels.h"
#include "fe-irc-server.h"

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
	char *serv;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 8, NULL, &channel, &user,
				  &host, &serv, &nick, &stat, &realname);

	/* split hops/realname */
	hops = realname;
	while (*realname != '\0' && *realname != ' ') realname++;
	while (*realname == ' ') realname++;
	if (realname > hops) realname[-1] = '\0';

	printformat(server, NULL, MSGLEVEL_CRAP, IRCTXT_WHO,
		    channel, nick, stat, hops, user, host, realname, serv);

	g_free(params);
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
	char *params, *ban, *setby, *tims;
	long secs;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel,
				  &ban, &setby, &tims);
	secs = *tims == '\0' ? 0 :
		(long) (time(NULL) - atol(tims));

	chanrec = irc_channel_find(server, channel);
	banrec = chanrec == NULL ? NULL : banlist_find(chanrec->banlist, ban);

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    *setby == '\0' ? IRCTXT_BANLIST : IRCTXT_BANLIST_LONG,
		    banrec == NULL ? 0 : g_slist_index(chanrec->banlist, banrec)+1,
		    channel, ban, setby, secs);

	g_free(params);
}

static void event_eban_list(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *ban, *setby, *tims;
	long secs;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 5, NULL, &channel,
				  &ban, &setby, &tims);
	secs = *tims == '\0' ? 0 :
		(long) (time(NULL) - atol(tims));

	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    *setby == '\0' ? IRCTXT_EBANLIST : IRCTXT_EBANLIST_LONG,
		    channel, ban, setby, secs);

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


static void event_invite_list(IRC_SERVER_REC *server, const char *data)
{
	const char *channel;
	char *params, *invite;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &invite);
	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_INVITELIST, channel, invite);
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
	char *params, *topic;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &channel, &topic);
	channel = get_visible_target(server, channel);
	printformat(server, channel, MSGLEVEL_CRAP,
		    IRCTXT_TOPIC, channel, topic);
	g_free(params);
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
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	if (!settings_get_bool("show_away_once") ||
	    last_away_nick == NULL || g_strcasecmp(last_away_nick, nick) != 0 ||
	    last_away_msg == NULL || g_strcasecmp(last_away_msg, awaymsg) != 0) {
		/* don't show the same away message
		   from the same nick all the time */
		g_free_not_null(last_away_nick);
		g_free_not_null(last_away_msg);
		last_away_nick = g_strdup(nick);
		last_away_msg = g_strdup(awaymsg);

		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_NICK_AWAY, nick, awaymsg);
	}
	g_free(params);
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

static void event_whois(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *user, *host, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick, &user,
				  &host, NULL, &realname);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS, nick, user, host, realname);
	g_free(params);
}

static void event_whois_idle(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *secstr, *signonstr, *rest, *timestr;
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
		timestr = my_asctime(signon);
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_IDLE_SIGNON,
			    nick, days, hours, mins, secs, timestr);
		g_free(timestr);
	}
	g_free(params);
}

static void event_whois_server(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *whoserver, *desc;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &nick, &whoserver, &desc);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_SERVER, nick, whoserver, desc);
	g_free(params);
}

static void event_whois_oper(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *type;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &type);
	/* type = "is an IRC Operator" */
	if (strlen(type) > 5) {
		type += 5;
		if (*type == ' ') type++;
	}
	if (*type == '\0') {
		/* shouldn't happen */
		type = "IRC Operator";
	}

	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_OPER, nick, type);
	g_free(params);
}

static void event_whois_registered(IRC_SERVER_REC *server, const char *data,
				   const char *orignick, const char *addr)
{
	char *params, *nick, *txt_identified;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &txt_identified);
	if (*txt_identified != '\0') {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REGISTERED, nick);
	} else {
		/* or /USERIP reply in undernet.. */
		print_event_received(server, data, orignick, FALSE);
	}
	g_free(params);
}

static void event_whois_help(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_WHOIS_HELP, nick);
	g_free(params);
}

static void event_whois_modes(IRC_SERVER_REC *server, const char *data,
			      const char *orignick)
{
	char *params, *nick, *modes;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick,
				  NULL, NULL, NULL, &modes);

	if (!ischannel(*nick)) {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_MODES, nick, modes);
	} else {
		/* OPN's dancer uses for channel forwarding */
		print_event_received(server, data, orignick, FALSE);
	}
	g_free(params);
}

static void event_whois_realhost(IRC_SERVER_REC *server, const char *data,
				 const char *orignick, const char *addr)
{
	char *params, *nick, *txt_real, *txt_hostname, *hostname;

	g_return_if_fail(data != NULL);

        /* <yournick> real hostname <nick> <hostname> */
	params = event_get_params(data, 5, NULL, &nick, &txt_real,
				  &txt_hostname, &hostname);
	if (strcmp(txt_real, "real") != 0 ||
	    strcmp(txt_hostname, "hostname") != 0) {
		/* <yournick> <nick> :... from <hostname> */
                g_free(params);
		params = event_get_params(data, 3, NULL, &nick, &hostname);

		hostname = strstr(hostname, "from ");
                if (hostname != NULL) hostname += 5;
	}

	if (hostname != NULL) {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REALHOST, nick, hostname, "");
	} else {
		/* OPN's dancer uses for end of /MAP */
		print_event_received(server, data, orignick, FALSE);
	}
	g_free(params);
}

static void event_whois_usermode326(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *usermode;

	g_return_if_fail(data != NULL);

        /* <yournick> <nick> :has oper privs: <mode> */
	params = event_get_params(data, 3, NULL, &nick, &usermode);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_USERMODE, nick, usermode);
        g_free(params);
}

static void event_whois_realhost327(IRC_SERVER_REC *server, const char *data,
				    const char *orignick, const char *addr)
{
	char *params, *nick, *hostname, *ip, *text;

	g_return_if_fail(data != NULL);

	/* <yournick> <hostname> <ip> :Real hostname/IP */
	params = event_get_params(data, 5, NULL, &nick, &hostname, &ip, &text);
	if (*text != '\0') {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REALHOST, nick, hostname, ip);
	} else {
		print_event_received(server, data, orignick, FALSE);
	}
	g_free(params);
}

static void event_whois_usermode(IRC_SERVER_REC *server, const char *data,
				 const char *orignick, const char *addr)
{
	char *params, *txt_usermodes, *nick, *usermode;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 4, NULL, &txt_usermodes,
				  &nick, &usermode);

	if (strcmp(txt_usermodes, "usermodes") == 0) {
		/* <yournick> usermodes <nick> usermode */
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_USERMODE, nick, usermode);
	} else {
		/* some servers use this as motd too..
		   and OPN's dancer for /MAP */
		print_event_received(server, data, orignick, FALSE);
	}
	g_free(params);
}

static void event_whois_special(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *str;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &str);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_SPECIAL, nick, str);
	g_free(params);
}

static void event_whowas(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *user, *host, *realname;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 6, NULL, &nick, &user,
				  &host, NULL, &realname);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOWAS, nick, user, host, realname);
	g_free(params);
}

static void event_whois_channels(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *chans;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &chans);

	/* sure - we COULD print the channel names as-is, but since the
	   colors, bolds, etc. are mostly just to fool people, I think we
	   should show the channel names as they REALLY are so they could
	   even be joined without any extra tricks. */
        chans = show_lowascii(chans);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_CHANNELS, nick, chans);
	g_free(chans);

	g_free(params);
}

static void event_whois_away(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *awaymsg;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &awaymsg);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_AWAY, nick, awaymsg);
	g_free(params);
}

static void event_end_of_whois(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	if (server->whois_found) {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_END_OF_WHOIS, nick);
	}
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

static void event_whois_auth(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick, *text;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, &nick, &text);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_EXTRA, nick, text);
	g_free(params);
}

static void event_end_of_whowas(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	if (server->whowas_found) {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_END_OF_WHOWAS, nick);
	}
	g_free(params);
}

static void event_target_unavailable(IRC_SERVER_REC *server, const char *data,
				     const char *nick, const char *addr)
{
	IRC_CHANNEL_REC *chanrec;
	char *params, *target;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &target);
	if (!ischannel(*target)) {
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

static void event_no_such_nick(IRC_SERVER_REC *server, const char *data)
{
	char *params, *nick;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &nick);
	printformat(server, nick, MSGLEVEL_CRAP, IRCTXT_NO_SUCH_NICK, nick);
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

static void event_duplicate_channel(IRC_SERVER_REC *server, const char *data)
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
	char *target, *args, *ptr;
	int format;

	g_return_if_fail(data != NULL);

        /* skip first param, it's always our nick */
	ptr = strchr(data, ' ');
	if (ptr == NULL)
		return;
	ptr++;

	if (!target_param)
		target = NULL;
	else {
                /* target parameter */
		target = ptr;
		ptr = strchr(target, ' ');
		if (ptr == NULL)
			return;

                target = g_strndup(target, (int) (ptr-target));
		ptr++;
	}

	/* param1 param2 ... :last parameter */
	if (*ptr == ':') {
                /* only one parameter */
		args = g_strdup(ptr+1);
	} else {
		args = g_strdup(ptr);
		ptr = strstr(args, " :");
		if (ptr != NULL)
			g_memmove(ptr+1, ptr+2, strlen(ptr+1));
	}

	format = nick == NULL || server->real_address == NULL ||
		strcmp(nick, server->real_address) == 0 ?
		IRCTXT_DEFAULT_EVENT : IRCTXT_DEFAULT_EVENT_SERVER;
	printformat(server, target, MSGLEVEL_CRAP, format,
		    nick, args, current_server_event);
	g_free(args);
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

	signal_add("event 221", (SIGNAL_FUNC) event_user_mode);
	signal_add("event 303", (SIGNAL_FUNC) event_ison);
	signal_add("event 353", (SIGNAL_FUNC) event_names_list);
	signal_add_first("event 366", (SIGNAL_FUNC) event_end_of_names);
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
	signal_add("event 306", (SIGNAL_FUNC) event_nowaway);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
	signal_add("event 301", (SIGNAL_FUNC) event_away);
	signal_add("event 311", (SIGNAL_FUNC) event_whois);
	signal_add("whois away", (SIGNAL_FUNC) event_whois_away);
	signal_add("whowas away", (SIGNAL_FUNC) event_whois_away);
	signal_add("event 312", (SIGNAL_FUNC) event_whois_server);
	signal_add("event 313", (SIGNAL_FUNC) event_whois_oper);
	signal_add("event 307", (SIGNAL_FUNC) event_whois_registered);
	signal_add("event 310", (SIGNAL_FUNC) event_whois_help);
	signal_add("event 326", (SIGNAL_FUNC) event_whois_usermode326);
	signal_add("event 327", (SIGNAL_FUNC) event_whois_realhost327);
	signal_add("event 379", (SIGNAL_FUNC) event_whois_modes);
	signal_add("event 378", (SIGNAL_FUNC) event_whois_realhost);
	signal_add("event 377", (SIGNAL_FUNC) event_whois_usermode);
	signal_add("event 320", (SIGNAL_FUNC) event_whois_special);
	signal_add("event 308", (SIGNAL_FUNC) event_whois_special);
	signal_add("event 275", (SIGNAL_FUNC) event_whois_special);
	signal_add("event 314", (SIGNAL_FUNC) event_whowas);
	signal_add("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_add("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_add("event 328", (SIGNAL_FUNC) event_chanserv_url);
	signal_add("event 330", (SIGNAL_FUNC) event_whois_auth);
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
	signal_add("event 375", (SIGNAL_FUNC) event_motd);
	signal_add("event 376", (SIGNAL_FUNC) event_motd);
	signal_add("event 372", (SIGNAL_FUNC) event_motd);
	signal_add("event 422", (SIGNAL_FUNC) event_motd);

        signal_add("default event numeric", (SIGNAL_FUNC) event_numeric);
	signal_add("event 001", (SIGNAL_FUNC) event_received);
	signal_add("event 004", (SIGNAL_FUNC) event_received);
	signal_add("event 254", (SIGNAL_FUNC) event_received);
	signal_add("event 364", (SIGNAL_FUNC) event_received);
	signal_add("event 365", (SIGNAL_FUNC) event_received);
	signal_add("event 381", (SIGNAL_FUNC) event_received);
	signal_add("event 421", (SIGNAL_FUNC) event_received);
	signal_add("event 432", (SIGNAL_FUNC) event_received);
	signal_add("event 436", (SIGNAL_FUNC) event_received);
	signal_add("event 438", (SIGNAL_FUNC) event_received);
	signal_add("event 465", (SIGNAL_FUNC) event_received);
	signal_add("event 439", (SIGNAL_FUNC) event_received);
	signal_add("event 479", (SIGNAL_FUNC) event_received);
	signal_add("event 482", (SIGNAL_FUNC) event_received);

	signal_add("event 368", (SIGNAL_FUNC) event_target_received);
	signal_add("event 347", (SIGNAL_FUNC) event_target_received);
	signal_add("event 349", (SIGNAL_FUNC) event_target_received);
	signal_add("event 442", (SIGNAL_FUNC) event_target_received);
	signal_add("event 477", (SIGNAL_FUNC) event_target_received);
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
	signal_remove("event 306", (SIGNAL_FUNC) event_nowaway);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
	signal_remove("event 301", (SIGNAL_FUNC) event_away);
	signal_remove("event 311", (SIGNAL_FUNC) event_whois);
	signal_remove("whois away", (SIGNAL_FUNC) event_whois_away);
	signal_remove("whowas away", (SIGNAL_FUNC) event_whois_away);
	signal_remove("event 312", (SIGNAL_FUNC) event_whois_server);
	signal_remove("event 313", (SIGNAL_FUNC) event_whois_oper);
	signal_remove("event 307", (SIGNAL_FUNC) event_whois_registered);
	signal_remove("event 310", (SIGNAL_FUNC) event_whois_help);
	signal_remove("event 326", (SIGNAL_FUNC) event_whois_usermode326);
	signal_remove("event 327", (SIGNAL_FUNC) event_whois_realhost327);
	signal_remove("event 379", (SIGNAL_FUNC) event_whois_modes);
	signal_remove("event 378", (SIGNAL_FUNC) event_whois_realhost);
	signal_remove("event 377", (SIGNAL_FUNC) event_whois_usermode);
	signal_remove("event 320", (SIGNAL_FUNC) event_whois_special);
	signal_remove("event 275", (SIGNAL_FUNC) event_whois_special);
	signal_remove("event 308", (SIGNAL_FUNC) event_whois_special);
	signal_remove("event 314", (SIGNAL_FUNC) event_whowas);
	signal_remove("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_remove("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_remove("event 328", (SIGNAL_FUNC) event_chanserv_url);
	signal_remove("event 330", (SIGNAL_FUNC) event_whois_auth);
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
	signal_remove("event 375", (SIGNAL_FUNC) event_motd);
	signal_remove("event 376", (SIGNAL_FUNC) event_motd);
	signal_remove("event 372", (SIGNAL_FUNC) event_motd);
	signal_remove("event 422", (SIGNAL_FUNC) event_motd);

        signal_remove("default event numeric", (SIGNAL_FUNC) event_numeric);
	signal_remove("event 001", (SIGNAL_FUNC) event_received);
	signal_remove("event 004", (SIGNAL_FUNC) event_received);
	signal_remove("event 254", (SIGNAL_FUNC) event_received);
	signal_remove("event 364", (SIGNAL_FUNC) event_received);
	signal_remove("event 365", (SIGNAL_FUNC) event_received);
	signal_remove("event 381", (SIGNAL_FUNC) event_received);
	signal_remove("event 421", (SIGNAL_FUNC) event_received);
	signal_remove("event 432", (SIGNAL_FUNC) event_received);
	signal_remove("event 436", (SIGNAL_FUNC) event_received);
	signal_remove("event 438", (SIGNAL_FUNC) event_received);
	signal_remove("event 465", (SIGNAL_FUNC) event_received);
	signal_remove("event 439", (SIGNAL_FUNC) event_received);
	signal_remove("event 479", (SIGNAL_FUNC) event_received);
	signal_remove("event 482", (SIGNAL_FUNC) event_received);

	signal_remove("event 368", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 347", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 349", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 442", (SIGNAL_FUNC) event_target_received);
	signal_remove("event 477", (SIGNAL_FUNC) event_target_received);
}
