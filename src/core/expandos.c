/*
 expandos.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "modules.h"
#include "signals.h"
#include "expandos.h"
#include "settings.h"
#include "commands.h"
#include "misc.h"
#include "irssi-version.h"

#include "servers.h"
#include "channels.h"
#include "queries.h"
#include "window-item-def.h"

#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif

#define MAX_EXPANDO_SIGNALS 10

typedef struct {
	EXPANDO_FUNC func;

        int signals;
	int signal_ids[MAX_EXPANDO_SIGNALS];
        int signal_args[MAX_EXPANDO_SIGNALS];
} EXPANDO_REC;

static int timer_tag;

static EXPANDO_REC *char_expandos[127];
static GHashTable *expandos;
static time_t client_start_time;
static char *last_sent_msg, *last_sent_msg_body;
static char *last_privmsg_from, *last_public_from;
static char *sysname, *sysrelease, *sysarch;
static const char *timestamp_format;

#define CHAR_EXPANDOS_COUNT \
	((int) (sizeof(char_expandos) / sizeof(char_expandos[0])))

/* Create expando - overrides any existing ones. */
void expando_create(const char *key, EXPANDO_FUNC func, ...)
{
        EXPANDO_REC *rec;
        const char *signal;
	va_list va;

	g_return_if_fail(key != NULL || *key == '\0');
	g_return_if_fail(func != NULL);

	if (key[1] != '\0')
		rec = g_hash_table_lookup(expandos, key);
	else {
		/* single character expando */
		rec = char_expandos[(int) *key];
	}

	if (rec != NULL)
		rec->signals = 0;
	else {
		rec = g_new0(EXPANDO_REC, 1);
                if (key[1] != '\0')
			g_hash_table_insert(expandos, g_strdup(key), rec);
		else
			char_expandos[(int) *key] = rec;
	}

	rec->func = func;

	va_start(va, func);
	while ((signal = (const char *) va_arg(va, const char *)) != NULL)
               expando_add_signal(key, signal, (int) va_arg(va, int));
        va_end(va);
}

static EXPANDO_REC *expando_find(const char *key)
{
	if (key[1] != '\0')
		return g_hash_table_lookup(expandos, key);
        else
		return char_expandos[(int) *key];
}

/* Add new signal to expando */
void expando_add_signal(const char *key, const char *signal, ExpandoArg arg)
{
	EXPANDO_REC *rec;

	g_return_if_fail(key != NULL);
	g_return_if_fail(signal != NULL);

        rec = expando_find(key);
        g_return_if_fail(rec != NULL);

	if (arg == EXPANDO_NEVER) {
                /* expando changes never */
		rec->signals = -1;
	} else if (rec->signals < MAX_EXPANDO_SIGNALS) {
		g_return_if_fail(rec->signals != -1);

		rec->signal_ids[rec->signals] = signal_get_uniq_id(signal);
		rec->signal_args[rec->signals] = arg;
                rec->signals++;
	}
}

/* Destroy expando */
void expando_destroy(const char *key, EXPANDO_FUNC func)
{
	gpointer origkey;
        EXPANDO_REC *rec;

	g_return_if_fail(key != NULL || *key == '\0');
	g_return_if_fail(func != NULL);

	if (key[1] == '\0') {
		/* single character expando */
		rec = char_expandos[(int) *key];
		if (rec != NULL && rec->func == func) {
			char_expandos[(int) *key] = NULL;
			g_free(rec);
		}
	} else if (g_hash_table_lookup_extended(expandos, key, &origkey,
						(gpointer *) &rec)) {
		if (rec->func == func) {
			g_free(origkey);
			g_hash_table_remove(expandos, key);
			g_free(rec);
		}
	}
}

void expando_bind(const char *key, int funccount, SIGNAL_FUNC *funcs)
{
	SIGNAL_FUNC func;
	EXPANDO_REC *rec;
        int n, arg;

	g_return_if_fail(key != NULL);
	g_return_if_fail(funccount >= 1);
	g_return_if_fail(funcs != NULL);
	g_return_if_fail(funcs[0] != NULL);

        rec = expando_find(key);
	g_return_if_fail(rec != NULL);

	if (rec->signals == 0) {
		/* it's unknown when this expando changes..
		   check it once in a second */
                signal_add("expando timer", funcs[EXPANDO_ARG_NONE]);
	}

	for (n = 0; n < rec->signals; n++) {
		arg = rec->signal_args[n];
		func = arg < funccount ? funcs[arg] : NULL;
		if (func == NULL) func = funcs[EXPANDO_ARG_NONE];

		signal_add_to_id(MODULE_NAME, 1, rec->signal_ids[n], func);
	}
}

void expando_unbind(const char *key, int funccount, SIGNAL_FUNC *funcs)
{
	SIGNAL_FUNC func;
	EXPANDO_REC *rec;
        int n, arg;

	g_return_if_fail(key != NULL);
	g_return_if_fail(funccount >= 1);
	g_return_if_fail(funcs != NULL);
	g_return_if_fail(funcs[0] != NULL);

        rec = expando_find(key);
	g_return_if_fail(rec != NULL);

	if (rec->signals == 0) {
		/* it's unknown when this expando changes..
		   check it once in a second */
                signal_remove("expando timer", funcs[EXPANDO_ARG_NONE]);
	}

	for (n = 0; n < rec->signals; n++) {
		arg = rec->signal_args[n];
		func = arg < funccount ? funcs[arg] : NULL;
		if (func == NULL) func = funcs[EXPANDO_ARG_NONE];

		signal_remove_id(rec->signal_ids[n], func);
	}
}

EXPANDO_FUNC expando_find_char(char chr)
{
	g_return_val_if_fail(chr < CHAR_EXPANDOS_COUNT, NULL);

	return char_expandos[(int) chr] == NULL ? NULL :
		char_expandos[(int) chr]->func;
}

EXPANDO_FUNC expando_find_long(const char *key)
{
	EXPANDO_REC *rec = g_hash_table_lookup(expandos, key);
	return rec == NULL ? NULL : rec->func;
}

/* last person who sent you a MSG */
static char *expando_lastmsg(SERVER_REC *server, void *item, int *free_ret)
{
	return last_privmsg_from;
}

/* last person to whom you sent a MSG */
static char *expando_lastmymsg(SERVER_REC *server, void *item, int *free_ret)
{
	return last_sent_msg;
}

/* last person to send a public message to a channel you are on */
static char *expando_lastpublic(SERVER_REC *server, void *item, int *free_ret)
{
	return last_public_from;
}

/* text of your AWAY message, if any */
static char *expando_awaymsg(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->away_reason;
}

/* body of last MSG you sent */
static char *expando_lastmymsg_body(SERVER_REC *server, void *item, int *free_ret)
{
	return last_sent_msg_body;
}

/* current channel */
static char *expando_channel(SERVER_REC *server, void *item, int *free_ret)
{
	return !IS_CHANNEL(item) ? NULL : CHANNEL(item)->name;
}

/* time client was started, $time() format */
static char *expando_clientstarted(SERVER_REC *server, void *item, int *free_ret)
{
        *free_ret = TRUE;
	return g_strdup_printf("%ld", (long) client_start_time);
}

/* channel you were last INVITEd to */
static char *expando_last_invite(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->last_invite;
}

/* client version text string */
static char *expando_version(SERVER_REC *server, void *item, int *free_ret)
{
	return IRSSI_VERSION;
}

/* current value of CMDCHARS */
static char *expando_cmdchars(SERVER_REC *server, void *item, int *free_ret)
{
	return (char *) settings_get_str("cmdchars");
}

/* modes of current channel, if any */
static char *expando_chanmode(SERVER_REC *server, void *item, int *free_ret)
{
	return !IS_CHANNEL(item) ? NULL : CHANNEL(item)->mode;
}

/* current nickname */
static char *expando_nick(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->nick;
}

/* value of STATUS_OPER if you are an irc operator */
static char *expando_statusoper(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL || !server->server_operator ? "" :
		(char *) settings_get_str("STATUS_OPER");
}

/* if you are a channel operator in $C, expands to a '@' */
static char *expando_chanop(SERVER_REC *server, void *item, int *free_ret)
{
	return IS_CHANNEL(item) && CHANNEL(item)->chanop ? "@" : "";
}

/* nickname of whomever you are QUERYing */
static char *expando_query(SERVER_REC *server, void *item, int *free_ret)
{
	return !IS_QUERY(item) ? "" : QUERY(item)->name;
}

/* version of current server */
static char *expando_serverversion(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->version;
}

/* target of current input (channel or QUERY nickname) */
static char *expando_target(SERVER_REC *server, void *item, int *free_ret)
{
	return item == NULL ? "" : ((WI_ITEM_REC *) item)->name;
}

/* client release date (numeric version string) */
static char *expando_releasedate(SERVER_REC *server, void *item, int *free_ret)
{
	return IRSSI_VERSION_DATE;
}

/* current working directory */
static char *expando_workdir(SERVER_REC *server, void *item, int *free_ret)
{
	*free_ret = TRUE;
	return g_get_current_dir();
}

/* value of REALNAME */
static char *expando_realname(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->connrec->realname;
}

/* time of day (hh:mm) */
static char *expando_time(SERVER_REC *server, void *item, int *free_ret)
{
	time_t now;
	struct tm *tm;
        char str[256];

        now = time(NULL);
	tm = localtime(&now);

	if (strftime(str, sizeof(str), timestamp_format, tm) == 0)
                return "";

	*free_ret = TRUE;
        return g_strdup(str);
}

/* a literal '$' */
static char *expando_dollar(SERVER_REC *server, void *item, int *free_ret)
{
	return "$";
}

/* system name */
static char *expando_sysname(SERVER_REC *server, void *item, int *free_ret)
{
	return sysname;
}

/* system release */
static char *expando_sysrelease(SERVER_REC *server, void *item, int *free_ret)
{
        return sysrelease;
}

/* system architecture */
static char *expando_sysarch(SERVER_REC *server, void *item, int *free_ret)
{
        return sysarch;
}

/* Topic of active channel (or address of queried nick) */
static char *expando_topic(SERVER_REC *server, void *item, int *free_ret)
{
	return IS_CHANNEL(item) ? CHANNEL(item)->topic :
		IS_QUERY(item) ? QUERY(item)->address : "";
}

/* Server tag */
static char *expando_servertag(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->tag;
}

/* Server chatnet */
static char *expando_chatnet(SERVER_REC *server, void *item, int *free_ret)
{
	return server == NULL ? "" : server->connrec->chatnet;
}

static void sig_message_public(SERVER_REC *server, const char *msg,
			       const char *nick, const char *address,
			       const char *target)
{
	g_free_not_null(last_public_from);
	last_public_from = g_strdup(nick);
}

static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *address)
{
	g_free_not_null(last_privmsg_from);
	last_privmsg_from = g_strdup(nick);
}

static void sig_message_own_private(SERVER_REC *server, const char *msg,
				    const char *target, const char *origtarget)
{
	g_return_if_fail(server != NULL);
	g_return_if_fail(msg != NULL);

	if (target != NULL) {
		if (target != last_sent_msg) {
			g_free_not_null(last_sent_msg);
			last_sent_msg = g_strdup(target);
		}
		g_free_not_null(last_sent_msg_body);
		last_sent_msg_body = g_strdup(msg);
	}
}

static int sig_timer(void)
{
        signal_emit("expando timer", 0);
        return 1;
}

static void read_settings(void)
{
        timestamp_format = settings_get_str("timestamp_format");
}

void expandos_init(void)
{
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname un;
#endif
	settings_add_str("misc", "STATUS_OPER", "*");
	settings_add_str("misc", "timestamp_format", "%H:%M");

	client_start_time = time(NULL);
	last_sent_msg = NULL; last_sent_msg_body = NULL;
	last_privmsg_from = NULL; last_public_from = NULL;

        sysname = sysrelease = sysarch = NULL;
#ifdef HAVE_SYS_UTSNAME_H
	if (uname(&un) == 0) {
		sysname = g_strdup(un.sysname);
		sysrelease = g_strdup(un.release);
		sysarch = g_strdup(un.machine);
	}
#endif

	memset(char_expandos, 0, sizeof(char_expandos));
	expandos = g_hash_table_new((GHashFunc) g_str_hash,
				    (GCompareFunc) g_str_equal);

	expando_create(",", expando_lastmsg,
		       "message private", EXPANDO_ARG_SERVER, NULL);
	expando_create(".", expando_lastmymsg,
		       "command msg", EXPANDO_ARG_NONE, NULL);
	expando_create(";", expando_lastpublic,
		       "message public", EXPANDO_ARG_SERVER, NULL);
	expando_create("A", expando_awaymsg,
		       "away mode changed", EXPANDO_ARG_NONE, NULL);
	expando_create("B", expando_lastmymsg_body,
		       "command msg", EXPANDO_ARG_NONE, NULL);
	expando_create("C", expando_channel,
		       "window changed", EXPANDO_ARG_NONE,
		       "window item changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("F", expando_clientstarted,
		       "", EXPANDO_NEVER, NULL);
	expando_create("I", expando_last_invite, NULL);
	expando_create("J", expando_version,
		       "", EXPANDO_NEVER, NULL);
	expando_create("K", expando_cmdchars,
		       "setup changed", EXPANDO_ARG_NONE, NULL);
	expando_create("M", expando_chanmode,
		       "window changed", EXPANDO_ARG_NONE,
		       "window item changed", EXPANDO_ARG_WINDOW,
		       "channel mode changed", EXPANDO_ARG_WINDOW_ITEM, NULL);
	expando_create("N", expando_nick,
		       "window changed", EXPANDO_ARG_NONE,
		       "window server changed", EXPANDO_ARG_WINDOW,
                       "server nick changed", EXPANDO_ARG_SERVER, NULL);
	expando_create("O", expando_statusoper,
		       "setup changed", EXPANDO_ARG_NONE,
		       "window changed", EXPANDO_ARG_NONE,
		       "window server changed", EXPANDO_ARG_WINDOW,
		       "user mode changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("P", expando_chanop,
		       "window changed", EXPANDO_ARG_NONE,
		       "window item changed", EXPANDO_ARG_WINDOW,
		       "nick mode changed", EXPANDO_ARG_WINDOW_ITEM, NULL);
	expando_create("Q", expando_query,
		       "window changed", EXPANDO_ARG_NONE,
		       "window item changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("R", expando_serverversion,
		       "window changed", EXPANDO_ARG_NONE,
		       "window server changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("T", expando_target,
		       "window changed", EXPANDO_ARG_NONE,
		       "window item changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("V", expando_releasedate,
		       "", EXPANDO_NEVER, NULL);
	expando_create("W", expando_workdir, NULL);
	expando_create("Y", expando_realname,
		       "window changed", EXPANDO_ARG_NONE,
		       "window server changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("Z", expando_time, NULL);
	expando_create("$", expando_dollar,
		       "", EXPANDO_NEVER, NULL);

	expando_create("sysname", expando_sysname,
		       "", EXPANDO_NEVER, NULL);
	expando_create("sysrelease", expando_sysrelease,
		       "", EXPANDO_NEVER, NULL);
	expando_create("sysarch", expando_sysarch,
		       "", EXPANDO_NEVER, NULL);
	expando_create("topic", expando_topic,
		       "window changed", EXPANDO_ARG_NONE,
		       "window item changed", EXPANDO_ARG_WINDOW,
		       "channel topic changed", EXPANDO_ARG_WINDOW_ITEM,
		       "query address changed", EXPANDO_ARG_WINDOW_ITEM, NULL);
	expando_create("tag", expando_servertag,
		       "window changed", EXPANDO_ARG_NONE,
		       "window server changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("chatnet", expando_chatnet,
		       "window changed", EXPANDO_ARG_NONE,
		       "window server changed", EXPANDO_ARG_WINDOW, NULL);

	read_settings();

        timer_tag = g_timeout_add(1000, (GSourceFunc) sig_timer, NULL);
	signal_add("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add("message own_private", (SIGNAL_FUNC) sig_message_own_private);
	signal_add_first("setup changed", (SIGNAL_FUNC) read_settings);
}

void expandos_deinit(void)
{
	int n;

	for (n = 0; n < CHAR_EXPANDOS_COUNT; n++)
		g_free_not_null(char_expandos[n]);

	expando_destroy("sysname", expando_sysname);
	expando_destroy("sysrelease", expando_sysrelease);
	expando_destroy("sysarch", expando_sysarch);
	expando_destroy("topic", expando_topic);
	expando_destroy("tag", expando_servertag);
	expando_destroy("chatnet", expando_chatnet);

        g_hash_table_destroy(expandos);

	g_free_not_null(last_sent_msg); g_free_not_null(last_sent_msg_body);
	g_free_not_null(last_privmsg_from); g_free_not_null(last_public_from);
	g_free_not_null(sysname); g_free_not_null(sysrelease);
        g_free_not_null(sysarch);

        g_source_remove(timer_tag);
	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("message own_private", (SIGNAL_FUNC) sig_message_own_private);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
