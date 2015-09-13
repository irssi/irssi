/* Copyright (C) 1999-2004 Timo Sirainen */

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"
#include "recode.h"

#include "irc-servers.h"

#include "printtext.h"

static void event_whois(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *user, *host, *realname, *recoded;

	g_return_if_fail(data != NULL);

	event_get_params(data, 6, NULL, &nick, &user,
			 &host, NULL, &realname);
	recoded = recode_in(SERVER(server), realname, nick);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS, nick, user, host, recoded);
	g_free(recoded);
}

static void event_whois_special(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *str;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3 | PARAM_FLAG_GETREST, NULL, &nick, &str);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_SPECIAL, nick, str);
}

static void event_whois_idle(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *secstr, *signonstr, *rest, *timestr;
	long days, hours, mins, secs;
	time_t signon;

	g_return_if_fail(data != NULL);

	event_get_params(data, 5 | PARAM_FLAG_GETREST, NULL,
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
}

static void event_whois_server(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *whoserver, *desc;

	g_return_if_fail(data != NULL);

	event_get_params(data, 4, NULL, &nick, &whoserver, &desc);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_SERVER, nick, whoserver, desc);
}

static void event_whois_oper(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *type;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3, NULL, &nick, &type);

	/* Bugfix: http://bugs.irssi.org/?do=details&task_id=99
	 * Author: Geert Hauwaerts <geert@irssi.org>
	 * Date:   Wed Sep 15 20:17:24 CEST 2004
	 */

	if ((!strncmp(type, "is an ", 6)) || (!strncmp(type, "is a ", 5))) {
		type += 5;
		if (*type == ' ') type++;
	}

	if (*type == '\0')
		type = "IRC Operator";

	printformat(server, nick, MSGLEVEL_CRAP,
		IRCTXT_WHOIS_OPER, nick, type);
}

static void event_whois_modes(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *modes;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3 | PARAM_FLAG_GETREST, NULL, &nick, &modes);
	if (!strncmp(modes, "is using modes ", 15))
		modes += 15;
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_MODES, nick, modes);
}

static void event_whois_realhost(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *txt_real, *txt_hostname, *hostname;

	g_return_if_fail(data != NULL);

        /* <yournick> real hostname <nick> <hostname> */
	event_get_params(data, 5, NULL, &nick, &txt_real,
			 &txt_hostname, &hostname);
	if (g_strcmp0(txt_real, "real") != 0 ||
	    g_strcmp0(txt_hostname, "hostname") != 0) {
		/* <yournick> <nick> :... from <hostname> */
		event_get_params(data, 3, NULL, &nick, &hostname);

		hostname = strstr(hostname, "from ");
                if (hostname != NULL) hostname += 5;
	}

	if (hostname != NULL) {
		if (!strncmp(hostname, "*@", 2))
			hostname += 2;
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REALHOST, nick, hostname, "");
	} else {
		event_whois_special(server, data);
	}
}

static void event_whois_usermode326(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *usermode;

	g_return_if_fail(data != NULL);

        /* <yournick> <nick> :has oper privs: <mode> */
	event_get_params(data, 3, NULL, &nick, &usermode);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_USERMODE, nick, usermode);
}

static void event_whois_realhost327(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *hostname, *ip, *text;

	g_return_if_fail(data != NULL);

	/* <yournick> <hostname> <ip> :Real hostname/IP */
	event_get_params(data, 5, NULL, &nick, &hostname, &ip, &text);
	if (*text != '\0') {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REALHOST, nick, hostname, ip);
	} else {
		event_whois_special(server, data);
	}
}

static void event_whois_realhost338(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *arg1, *arg2, *arg3;

	g_return_if_fail(data != NULL);

	/*
	 * :<server> 338 <yournick> <nick> <user>@<host> <ip> :Actual user@host, actual IP
	 * (ircu) or
	 * :<server> 338 <yournick> <nick> <ip> :actually using host
	 * (ratbox)
	 */
	event_get_params(data, 5, NULL, &nick, &arg1, &arg2, &arg3);
	if (*arg3 != '\0') {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REALHOST, nick, arg1, arg2);
	} else if (*arg2 != '\0') {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_REALHOST, nick, arg1, "");
	} else {
		event_whois_special(server, data);
	}
}

static void event_whois_usermode(IRC_SERVER_REC *server, const char *data)
{
	char *txt_usermodes, *nick, *usermode;

	g_return_if_fail(data != NULL);

	event_get_params(data, 4, NULL, &txt_usermodes,
				  &nick, &usermode);

	if (g_strcmp0(txt_usermodes, "usermodes") == 0) {
		/* <yournick> usermodes <nick> usermode */
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_WHOIS_USERMODE, nick, usermode);
	} else {
		event_whois_special(server, data);
	}
}

static void hide_safe_channel_id(IRC_SERVER_REC *server, char *chans)
{
	const char *idchan, *nick_flags;
	char *p, *dest, *end, id;
	int count, length, chanstart;

	if (!server->isupport_sent)
		idchan = "!:5";
	else {
		idchan = g_hash_table_lookup(server->isupport, "IDCHAN");
		if (idchan == NULL)
			return;
	}
	nick_flags = server->get_nick_flags(SERVER(server));

	while (*idchan != '\0') {
		id = *idchan;
		if (idchan[1] != ':')
			return;

		length = strtoul(idchan+2, &end, 10);
		if (*end == ',')
			end++;
		else if (*end != '\0')
			return;
		idchan = end;

		count = 0;
		chanstart = TRUE;
		for (dest = p = chans; *p != '\0'; p++) {
			if (count > 0)
				count--;
			else {
				if (*p == ' ')
					chanstart = TRUE;
				else {
					if (chanstart && *p == id)
						count = length;
					chanstart = chanstart && strchr(nick_flags, *p);
				}
				*dest++ = *p;
			}
		}
		*dest = '\0';
	}
}

static void event_whois_channels(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *chans, *recoded;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3, NULL, &nick, &chans);

	/* sure - we COULD print the channel names as-is, but since the
	   colors, bolds, etc. are mostly just to fool people, I think we
	   should show the channel names as they REALLY are so they could
	   even be joined without any extra tricks. */
	chans = show_lowascii(chans);
	if (settings_get_bool("whois_hide_safe_channel_id"))
		hide_safe_channel_id(server, chans);
	recoded = recode_in(SERVER(server), chans, nick);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_CHANNELS, nick, recoded);
	g_free(chans);

	g_free(recoded);
}

static void event_whois_away(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *awaymsg, *recoded;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3, NULL, &nick, &awaymsg);
	recoded = recode_in(SERVER(server), awaymsg, nick);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_AWAY, nick, recoded);
	g_free(recoded);
}

static void event_end_of_whois(IRC_SERVER_REC *server, const char *data)
{
	char *nick;

	g_return_if_fail(data != NULL);

	event_get_params(data, 2, NULL, &nick);
	if (server->whois_found) {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_END_OF_WHOIS, nick);
	}
}

static void event_whois_auth(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *text;

	g_return_if_fail(data != NULL);

	event_get_params(data, 3, NULL, &nick, &text);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOIS_EXTRA, nick, text);
}

static void event_whowas(IRC_SERVER_REC *server, const char *data)
{
	char *nick, *user, *host, *realname, *recoded;

	g_return_if_fail(data != NULL);

	event_get_params(data, 6, NULL, &nick, &user,
			 &host, NULL, &realname);
	recoded = recode_in(SERVER(server), realname, nick);
	printformat(server, nick, MSGLEVEL_CRAP,
		    IRCTXT_WHOWAS, nick, user, host, recoded);
	g_free(recoded);
}

static void event_end_of_whowas(IRC_SERVER_REC *server, const char *data)
{
	char *nick;

	g_return_if_fail(data != NULL);

	event_get_params(data, 2, NULL, &nick);
	if (server->whowas_found) {
		printformat(server, nick, MSGLEVEL_CRAP,
			    IRCTXT_END_OF_WHOWAS, nick);
	}
}

struct whois_event_table {
	int num;
	void (*func)(IRC_SERVER_REC *, const char *);
};

static struct whois_event_table events[] = {
	{ 312, event_whois_server },
	{ 326, event_whois_usermode326 },
	{ 327, event_whois_realhost327 },
	{ 338, event_whois_realhost338 },
	{ 379, event_whois_modes },
	{ 378, event_whois_realhost },
	{ 377, event_whois_usermode },
	{ 317, event_whois_idle },
	{ 330, event_whois_auth },
	{ 319, event_whois_channels },
	{ 0, NULL }
};

static void event_whois_default(IRC_SERVER_REC *server, const char *data)
{
	int i, num;

	num = atoi(current_server_event);
	for (i = 0; events[i].num != 0; i++) {
		if (events[i].num == num) {
			events[i].func(server, data);
			return;
		}
	}

	event_whois_special(server, data);
}

void fe_whois_init(void)
{
	settings_add_bool("lookandfeel", "whois_hide_safe_channel_id", TRUE);

	signal_add("event 311", (SIGNAL_FUNC) event_whois);
	signal_add("event 312", (SIGNAL_FUNC) event_whois_server);
	/* readding this events fixes the printing of /whois -yes *
	   Bug http://bugs.irssi.org/?do=details&task_id=123 */
	signal_add("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_add("event 319", (SIGNAL_FUNC) event_whois_channels);
	signal_add("event 313", (SIGNAL_FUNC) event_whois_oper);
	signal_add("event 330", (SIGNAL_FUNC) event_whois_auth);
	signal_add("event 377", (SIGNAL_FUNC) event_whois_usermode);
	signal_add("event 378", (SIGNAL_FUNC) event_whois_realhost);
	signal_add("event 379", (SIGNAL_FUNC) event_whois_modes);
	signal_add("event 327", (SIGNAL_FUNC) event_whois_realhost327);
	signal_add("event 326", (SIGNAL_FUNC) event_whois_usermode326);
	signal_add("event 338", (SIGNAL_FUNC) event_whois_realhost338);
	signal_add("whois away", (SIGNAL_FUNC) event_whois_away);
	signal_add("whois oper", (SIGNAL_FUNC) event_whois_oper);
	signal_add("whowas away", (SIGNAL_FUNC) event_whois_away);
	signal_add("whois default event", (SIGNAL_FUNC) event_whois_default);
	signal_add("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_add("event 314", (SIGNAL_FUNC) event_whowas);
	signal_add("event 369", (SIGNAL_FUNC) event_end_of_whowas);
}

void fe_whois_deinit(void)
{
	signal_remove("event 311", (SIGNAL_FUNC) event_whois);
	signal_remove("event 312", (SIGNAL_FUNC) event_whois_server);
	signal_remove("event 317", (SIGNAL_FUNC) event_whois_idle);
	signal_remove("event 319", (SIGNAL_FUNC) event_whois_channels);
	signal_remove("event 313", (SIGNAL_FUNC) event_whois_oper);
	signal_remove("event 330", (SIGNAL_FUNC) event_whois_auth);
	signal_remove("event 377", (SIGNAL_FUNC) event_whois_usermode);
	signal_remove("event 378", (SIGNAL_FUNC) event_whois_realhost);
	signal_remove("event 379", (SIGNAL_FUNC) event_whois_modes);
	signal_remove("event 327", (SIGNAL_FUNC) event_whois_realhost327);
	signal_remove("event 326", (SIGNAL_FUNC) event_whois_usermode326);
	signal_remove("event 338", (SIGNAL_FUNC) event_whois_realhost338);
	signal_remove("whois away", (SIGNAL_FUNC) event_whois_away);
	signal_remove("whois oper", (SIGNAL_FUNC) event_whois_oper);
	signal_remove("whowas away", (SIGNAL_FUNC) event_whois_away);
	signal_remove("whois default event", (SIGNAL_FUNC) event_whois_default);
	signal_remove("event 318", (SIGNAL_FUNC) event_end_of_whois);
	signal_remove("event 314", (SIGNAL_FUNC) event_whowas);
	signal_remove("event 369", (SIGNAL_FUNC) event_end_of_whowas);
}
