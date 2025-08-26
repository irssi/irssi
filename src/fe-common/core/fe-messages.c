/*
 fe-messages.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/nicklist.h>
#include <irssi/src/core/ignore.h>

#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/fe-common/core/fe-queries.h>
#include <irssi/src/fe-common/core/hilight-text.h>
#include <irssi/src/fe-common/core/printtext.h>

/* Forward declarations for nick column functions */
void update_nick_context(const char *nick, const char *mode);
void clear_nick_context(void);

#define ishighalnum(c) ((unsigned char) (c) >= 128 || i_isalnum(c))
#define isnickchar(a)                                                                              \
	(i_isalnum(a) || (a) == '`' || (a) == '-' || (a) == '_' || (a) == '[' || (a) == ']' ||     \
	 (a) == '{' || (a) == '}' || (a) == '|' || (a) == '\\' || (a) == '^')

GHashTable *printnicks;

/* convert _underlined_, /italics/, and *bold* words (and phrases) to use real
   underlining or bolding */
char *expand_emphasis(WI_ITEM_REC *item, const char *text)
{
	GString *str;
	char *ret;
	int pos;
	int emphasis_italics;

	g_return_val_if_fail(text != NULL, NULL);

	emphasis_italics = settings_get_bool("emphasis_italics");

	str = g_string_new(text);

	for (pos = 0; pos < str->len; pos++) {
		char type, *bgn, *end;

		bgn = str->str + pos;

		if (*bgn == '*')
			type = 2; /* bold */
		else if (*bgn == '/' && emphasis_italics)
			type = 29; /* italics */
		else if (*bgn == '_')
			type = 31; /* underlined */
		else
			continue;

		/* check that the beginning marker starts a word, and
		   that the matching end marker ends a word */
		if ((pos > 0 && bgn[-1] != ' ') || !ishighalnum(bgn[1]))
			continue;
		if ((end = strchr(bgn + 1, *bgn)) == NULL)
			continue;
		if (!ishighalnum(end[-1]) || ishighalnum(end[1]) || end[1] == type ||
		    end[1] == '*' || end[1] == '_' ||
		    /* special case for italics to not emphasise
		       common paths by skipping /.../.X */
		    (type == 29 && i_ispunct(end[1]) && ishighalnum(end[2])))
			continue;

		if (IS_CHANNEL(item)) {
			/* check that this isn't a _nick_, we don't want to
			   use emphasis on them. */
			int found;
			char c;
			char *end2;

			/* check if _foo_ is a nick */
			c = end[1];
			end[1] = '\0';
			found = nicklist_find(CHANNEL(item), bgn) != NULL;
			end[1] = c;
			if (found)
				continue;

			/* check if the whole 'word' (e.g. "_foo_^") is a nick
			   in "_foo_^ ", end will be the second _, end2 the ^ */
			end2 = end;
			while (isnickchar(end2[1]))
				end2++;
			c = end2[1];
			end2[1] = '\0';
			found = nicklist_find(CHANNEL(item), bgn) != NULL;
			end2[1] = c;
			if (found)
				continue;
		}

		/* allow only *word* emphasis, not *multiple words* */
		if (!settings_get_bool("emphasis_multiword")) {
			char *c;
			for (c = bgn + 1; c != end; c++) {
				if (!ishighalnum(*c))
					break;
			}
			if (c != end)
				continue;
		}

		if (settings_get_bool("emphasis_replace")) {
			*bgn = *end = type;
			pos += (end - bgn);
		} else {
			g_string_insert_c(str, pos, type);
			pos += (end - bgn) + 2;
			g_string_insert_c(str, pos++, type);
		}
	}

	ret = g_string_free_and_steal(str);
	return ret;
}

static char *channel_get_nickmode_rec(NICK_REC *nickrec)
{
	char *emptystr;
	char *nickmode;

	if (!settings_get_bool("show_nickmode"))
		return g_strdup("");

	emptystr = settings_get_bool("show_nickmode_empty") ? " " : "";

	if (nickrec == NULL || nickrec->prefixes[0] == '\0')
		nickmode = g_strdup(emptystr);
	else {
		nickmode = g_malloc(2);
		nickmode[0] = nickrec->prefixes[0];
		nickmode[1] = '\0';
	}
	return nickmode;
}

char *channel_get_nickmode(CHANNEL_REC *channel, const char *nick)
{
	g_return_val_if_fail(nick != NULL, NULL);

	return channel_get_nickmode_rec(channel == NULL ? NULL : nicklist_find(channel, nick));
}

static void sig_message_public(SERVER_REC *server, const char *msg, const char *nick,
                               const char *address, const char *target, NICK_REC *nickrec)
{
	CHANNEL_REC *chanrec;
	const char *printnick;
	int for_me, print_channel, level;
	char *nickmode, *color, *freemsg = NULL;
	HILIGHT_REC *hilight;
	TEXT_DEST_REC dest;

	/* NOTE: this may return NULL if some channel is just closed with
	   /WINDOW CLOSE and server still sends the few last messages */
	chanrec = channel_find(server, target);
	if (nickrec == NULL && chanrec != NULL)
		nickrec = nicklist_find(chanrec, nick);

	for_me = !settings_get_bool("hilight_nick_matches") ?
	             FALSE :
	         !settings_get_bool("hilight_nick_matches_everywhere") ?
	             nick_match_msg(chanrec, msg, server->nick) :
	             nick_match_msg_everywhere(chanrec, msg, server->nick);
	hilight =
	    for_me ? NULL : hilight_match_nick(server, target, nick, address, MSGLEVEL_PUBLIC, msg);
	color = (hilight == NULL) ? NULL : hilight_get_color(hilight);

	print_channel = chanrec == NULL || !window_item_is_active((WI_ITEM_REC *) chanrec);
	if (!print_channel && settings_get_bool("print_active_channel") &&
	    window_item_window((WI_ITEM_REC *) chanrec)->items->next != NULL)
		print_channel = TRUE;

	level = MSGLEVEL_PUBLIC;
	if (for_me)
		level |= MSGLEVEL_HILIGHT;

	ignore_check_plus(server, nick, address, target, msg, &level, FALSE);
	if (level & MSGLEVEL_NOHILIGHT) {
		for_me = FALSE;
		g_free_and_null(color);
		level &= ~MSGLEVEL_HILIGHT;
	}

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis((WI_ITEM_REC *) chanrec, msg);

	/* get nick mode & nick what to print the msg with
	   (in case there's multiple identical nicks) */
	nickmode = channel_get_nickmode_rec(nickrec);
	printnick = nickrec == NULL ? nick : g_hash_table_lookup(printnicks, nickrec);
	if (printnick == NULL)
		printnick = nick;

	/* Update nick context for expandos */
	if (settings_get_bool("nick_column_enabled")) {
		update_nick_context(printnick, nickmode);
	}

	format_create_dest(&dest, server, target, level, NULL);
	dest.address = address;
	dest.nick = nick;
	if (color != NULL) {
		/* highlighted nick */
		hilight_update_text_dest(&dest, hilight);
		if (!print_channel) /* message to active channel in window */
			printformat_dest(&dest, TXT_PUBMSG_HILIGHT, color, printnick, msg,
			                 nickmode);
		else /* message to not existing/active channel */
			printformat_dest(&dest, TXT_PUBMSG_HILIGHT_CHANNEL, color, printnick,
			                 target, msg, nickmode);
	} else {
		if (!print_channel)
			printformat_dest(&dest, for_me ? TXT_PUBMSG_ME : TXT_PUBMSG, printnick, msg,
			                 nickmode);
		else
			printformat_dest(&dest, for_me ? TXT_PUBMSG_ME_CHANNEL : TXT_PUBMSG_CHANNEL,
			                 printnick, target, msg, nickmode);
	}

	g_free_not_null(nickmode);
	g_free_not_null(freemsg);
	g_free_not_null(color);
}

static void sig_message_private(SERVER_REC *server, const char *msg, const char *nick,
                                const char *address, const char *target)
{
	QUERY_REC *query;
	char *freemsg = NULL;
	int level = MSGLEVEL_MSGS;

	/* own message returned by bouncer? */
	int own = (!g_strcmp0(nick, server->nick));

	query = query_find(server, own ? target : nick);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis((WI_ITEM_REC *) query, msg);

	ignore_check_plus(server, nick, address, NULL, msg, &level, FALSE);

	if (own) {
		printformat(server, target, level,
		            query == NULL ? TXT_OWN_MSG_PRIVATE : TXT_OWN_MSG_PRIVATE_QUERY, target,
		            msg, server->nick);
	} else {
		printformat(server, nick, level,
		            query == NULL ? TXT_MSG_PRIVATE : TXT_MSG_PRIVATE_QUERY, nick, address,
		            msg);
	}

	g_free_not_null(freemsg);
}

static void sig_message_own_public(SERVER_REC *server, const char *msg, const char *target)
{
	WINDOW_REC *window;
	CHANNEL_REC *channel;
	char *nickmode;
	char *freemsg = NULL;
	int print_channel;
	channel = channel_find(server, target);
	if (channel != NULL)
		target = channel->visible_name;

	nickmode = channel_get_nickmode(channel, server->nick);

	/* Update nick context for expandos */
	if (settings_get_bool("nick_column_enabled")) {
		update_nick_context(server->nick, nickmode);
	}

	window = channel == NULL ? NULL : window_item_window((WI_ITEM_REC *) channel);

	print_channel = window == NULL || window->active != (WI_ITEM_REC *) channel;

	if (!print_channel && settings_get_bool("print_active_channel") && window != NULL &&
	    g_slist_length(window->items) > 1)
		print_channel = TRUE;

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis((WI_ITEM_REC *) channel, msg);

	if (!print_channel) {
		printformat(server, target, MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		            TXT_OWN_MSG, server->nick, msg, nickmode);
	} else {
		printformat(server, target, MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		            TXT_OWN_MSG_CHANNEL, server->nick, target, msg, nickmode);
	}

	g_free_not_null(nickmode);
	g_free_not_null(freemsg);
}

static void sig_message_own_private(SERVER_REC *server, const char *msg, const char *target,
                                    const char *origtarget)
{
	QUERY_REC *query;
	char *freemsg = NULL;

	g_return_if_fail(server != NULL);
	g_return_if_fail(msg != NULL);
	if (target == NULL) {
		/* this should only happen if some special target failed and
		   we should display some error message. currently the special
		   targets are only ',' and '.'. */
		g_return_if_fail(g_strcmp0(origtarget, ",") == 0 ||
		                 g_strcmp0(origtarget, ".") == 0);

		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		            *origtarget == ',' ? TXT_NO_MSGS_GOT : TXT_NO_MSGS_SENT);
		signal_stop();
		return;
	}

	query = privmsg_get_query(server, target, TRUE, MSGLEVEL_MSGS);

	if (settings_get_bool("emphasis"))
		msg = freemsg = expand_emphasis((WI_ITEM_REC *) query, msg);

	printformat(server, target, MSGLEVEL_MSGS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
	            query == NULL ? TXT_OWN_MSG_PRIVATE : TXT_OWN_MSG_PRIVATE_QUERY, target, msg,
	            server->nick);

	g_free_not_null(freemsg);
}

static void sig_message_join(SERVER_REC *server, const char *channel, const char *nick,
                             const char *address, const char *account, const char *realname)
{
	int level = MSGLEVEL_JOINS;

	ignore_check_plus(server, nick, address, channel, NULL, &level, FALSE);

	if (settings_get_bool("show_extended_join")) {
		int txt;
		if (*account == '\0')
			txt = TXT_JOIN;
		else if (g_strcmp0("*", account) == 0)
			txt = TXT_JOIN_EXTENDED;
		else
			txt = TXT_JOIN_EXTENDED_ACCOUNT;
		printformat(server, channel, level, txt, nick, address, channel, account, realname);
	} else {
		printformat(server, channel, level, TXT_JOIN, nick, address, channel, account,
		            realname);
	}
}

static void sig_message_part(SERVER_REC *server, const char *channel, const char *nick,
                             const char *address, const char *reason)
{
	int level = MSGLEVEL_PARTS;

	ignore_check_plus(server, nick, address, channel, NULL, &level, FALSE);

	printformat(server, channel, level, TXT_PART, nick, address, channel, reason);
}

static void spread_server_message_to_windows(SERVER_REC *server, gboolean once, gboolean in_query,
                                             int base_level, int txt, int txt_once,
                                             const char *nick, const char *address,
                                             const char *data, const char *ignore_data)
{
	WINDOW_REC *window;
	GString *chans;
	GSList *tmp, *windows;
	char *print_channel;
	int count, level = base_level;

	if (ignore_check_plus(server, nick, address, NULL, ignore_data, &level, TRUE))
		return;

	print_channel = NULL;

	count = 0;
	windows = NULL;
	chans = g_string_new(NULL);
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec;
		level = base_level;
		rec = tmp->data;

		if (!nicklist_find(rec, nick)) {
			continue;
		}

		if (ignore_check_plus(server, nick, address, rec->visible_name, ignore_data, &level,
		                      TRUE)) {
			count++;
			continue;
		}

		if (print_channel == NULL || active_win->active == (WI_ITEM_REC *) rec) {
			print_channel = rec->visible_name;
		}

		if (once) {
			g_string_append_printf(chans, "%s,", rec->visible_name);
		} else {
			window = window_item_window((WI_ITEM_REC *) rec);
			if (g_slist_find(windows, window) == NULL) {
				windows = g_slist_prepend(windows, window);
				printformat(server, rec->visible_name, level, txt, nick, address,
				            data, rec->visible_name);
			}
		}
		count++;
	}
	g_slist_free(windows);

	if (!once && in_query) {
		/* check if you had query with the nick and
		   display the change there too */
		QUERY_REC *query = query_find(server, nick);
		if (query != NULL) {
			printformat(server, nick, level, txt, nick, address, data, "");
		}
	}

	if (once || count == 0) {
		if (chans->len > 0) {
			g_string_truncate(chans, chans->len - 1);
		}
		printformat(server, print_channel, base_level, count <= 1 ? txt : txt_once, nick,
		            address, data, chans->str);
	}
	g_string_free(chans, TRUE);
}

static void sig_message_host_changed(SERVER_REC *server, const char *nick, const char *address,
                                     const char *old_address)
{
	spread_server_message_to_windows(server, settings_get_bool("show_quit_once"), TRUE,
	                                 MSGLEVEL_JOINS, TXT_HOST_CHANGED, TXT_HOST_CHANGED, nick,
	                                 address, old_address, NULL);
}

static void sig_message_account_changed(SERVER_REC *server, const char *nick, const char *address,
                                        const char *account)
{
	gboolean logged_in;
	int txt;

	if (!settings_get_bool("show_account_notify"))
		return;

	logged_in = g_strcmp0("*", account) != 0;
	txt = logged_in ? TXT_LOGGED_IN : TXT_LOGGED_OUT;

	spread_server_message_to_windows(server, settings_get_bool("show_quit_once"), TRUE,
	                                 MSGLEVEL_MODES, txt, txt, nick, address, account,
	                                 "account");
}

static void sig_message_quit(SERVER_REC *server, const char *nick, const char *address,
                             const char *reason)
{
	spread_server_message_to_windows(server, settings_get_bool("show_quit_once"), TRUE,
	                                 MSGLEVEL_QUITS, TXT_QUIT, TXT_QUIT_ONCE, nick, address,
	                                 reason, reason);
}

static void sig_message_kick(SERVER_REC *server, const char *channel, const char *nick,
                             const char *kicker, const char *address, const char *reason)
{
	int level = MSGLEVEL_KICKS;

	ignore_check_plus(server, kicker, address, channel, reason, &level, FALSE);

	printformat(server, channel, level, TXT_KICK, nick, channel, kicker, reason, address);
}

static void print_nick_change_channel(SERVER_REC *server, const char *channel, const char *newnick,
                                      const char *oldnick, const char *address, int ownnick)
{
	int level;

	level = MSGLEVEL_NICKS;
	if (ownnick)
		level |= MSGLEVEL_NO_ACT;
	if (ignore_check_plus(server, oldnick, address, channel, newnick, &level, TRUE))
		return;

	printformat(server, channel, level, ownnick ? TXT_YOUR_NICK_CHANGED : TXT_NICK_CHANGED,
	            oldnick, newnick, channel, address);
}

static void print_nick_change(SERVER_REC *server, const char *newnick, const char *oldnick,
                              const char *address, int ownnick)
{
	GSList *tmp, *windows;
	int msgprint;

	msgprint = FALSE;

	/* Print to each channel where the nick is.
	   Don't print more than once to the same window. */
	windows = NULL;
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *channel = tmp->data;
		WINDOW_REC *window = window_item_window((WI_ITEM_REC *) channel);

		if (nicklist_find(channel, newnick) == NULL ||
		    g_slist_find(windows, window) != NULL)
			continue;

		windows = g_slist_append(windows, window);
		print_nick_change_channel(server, channel->visible_name, newnick, oldnick, address,
		                          ownnick);
		msgprint = TRUE;
	}

	g_slist_free(windows);

	if (!msgprint && ownnick) {
		printformat(server, NULL, MSGLEVEL_NICKS, TXT_YOUR_NICK_CHANGED, oldnick, newnick,
		            "", address);
	}
}

static void sig_message_nick(SERVER_REC *server, const char *newnick, const char *oldnick,
                             const char *address)
{
	print_nick_change(server, newnick, oldnick, address, FALSE);
}

static void sig_message_own_nick(SERVER_REC *server, const char *newnick, const char *oldnick,
                                 const char *address)
{
	if (!settings_get_bool("show_own_nickchange_once"))
		print_nick_change(server, newnick, oldnick, address, TRUE);
	else {
		printformat(server, NULL, MSGLEVEL_NICKS, TXT_YOUR_NICK_CHANGED, oldnick, newnick,
		            "", address);
	}
}

static void sig_message_invite(SERVER_REC *server, const char *channel, const char *nick,
                               const char *address)
{
	char *str;

	str = show_lowascii(channel);
	printformat(server, NULL, MSGLEVEL_INVITES, TXT_INVITE, nick, str, address);
	g_free(str);
}

static void sig_message_invite_other(SERVER_REC *server, const char *channel, const char *invited,
                                     const char *nick, const char *address)
{
	char *str;
	int level = MSGLEVEL_INVITES;

	ignore_check_plus(server, nick, address, channel, invited, &level, FALSE);

	str = show_lowascii(channel);
	printformat(server, channel, level, TXT_INVITE_OTHER, invited, nick, str, address);
	g_free(str);
}

static void sig_message_topic(SERVER_REC *server, const char *channel, const char *topic,
                              const char *nick, const char *address)
{
	int level = MSGLEVEL_TOPICS;

	ignore_check_plus(server, nick, address, channel, topic, &level, FALSE);

	printformat(server, channel, level, *topic != '\0' ? TXT_NEW_TOPIC : TXT_TOPIC_UNSET, nick,
	            channel, topic, address);
}

static void sig_message_away_notify(SERVER_REC *server, const char *nick, const char *addr,
                                    const char *awaymsg)
{
	int txt = *awaymsg == '\0' ? TXT_NOTIFY_UNAWAY_CHANNEL : TXT_NOTIFY_AWAY_CHANNEL;

	if (!settings_get_bool("away_notify_public"))
		return;

	spread_server_message_to_windows(server, FALSE, FALSE, MSGLEVEL_CRAP, txt, txt, nick, addr,
	                                 awaymsg, awaymsg);
}

static int printnick_exists(NICK_REC *first, NICK_REC *ignore, const char *nick)
{
	char *printnick;

	while (first != NULL) {
		if (first != ignore) {
			printnick = g_hash_table_lookup(printnicks, first);
			if (printnick != NULL && g_strcmp0(printnick, nick) == 0)
				return TRUE;
		}

		first = first->next;
	}

	return FALSE;
}

static NICK_REC *printnick_find_original(NICK_REC *nick)
{
	while (nick != NULL) {
		if (g_hash_table_lookup(printnicks, nick) == NULL)
			return nick;

		nick = nick->next;
	}

	return NULL;
}

static void sig_nicklist_new(CHANNEL_REC *channel, NICK_REC *nick)
{
	NICK_REC *firstnick;
	GString *newnick;
	char *nickhost, *p;
	int n;

	firstnick = g_hash_table_lookup(channel->nicks, nick->nick);
	if (firstnick->next == NULL)
		return;

	if (nick == channel->ownnick) {
		/* own nick is being added, might be a nick change and
		   someone else having the original nick already in use.. */
		nick = printnick_find_original(firstnick->next);
		if (nick == NULL)
			return; /* nope, we have it */
	}

	if (nick->host == NULL)
		return;

	/* identical nick already exists, have to change it somehow.. */
	p = strchr(nick->host, '@');
	if (p == NULL)
		p = nick->host;
	else
		p++;

	nickhost = g_strdup_printf("%s@%s", nick->nick, p);
	p = strchr(nickhost + strlen(nick->nick), '.');
	if (p != NULL)
		*p = '\0';

	if (!printnick_exists(firstnick, nick, nickhost)) {
		/* use nick@host */
		g_hash_table_insert(printnicks, nick, nickhost);
		return;
	}

	newnick = g_string_new(NULL);
	n = 2;
	do {
		g_string_printf(newnick, "%s%d", nickhost, n);
		n++;
	} while (printnick_exists(firstnick, nick, newnick->str));

	g_hash_table_insert(printnicks, nick, g_string_free_and_steal(newnick));
	g_free(nickhost);
}

static void sig_nicklist_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	char *nickname;

	nickname = g_hash_table_lookup(printnicks, nick);
	if (nickname != NULL) {
		g_free(nickname);
		g_hash_table_remove(printnicks, nick);
	}
}

static void sig_nicklist_changed(CHANNEL_REC *channel, NICK_REC *nick)
{
	sig_nicklist_remove(channel, nick);
	sig_nicklist_new(channel, nick);
}

static void sig_channel_joined(CHANNEL_REC *channel)
{
	NICK_REC *nick;
	char *nickname;

	/* channel->ownnick is set at this point - check if our own nick
	   has been changed, if it was set it back to the original nick and
	   change the previous original to something else */

	nickname = g_hash_table_lookup(printnicks, channel->ownnick);
	if (nickname == NULL)
		return;

	g_free(nickname);
	g_hash_table_remove(printnicks, channel->ownnick);

	/* our own nick is guaranteed to be the first in list */
	nick = channel->ownnick->next;
	while (nick != NULL) {
		if (g_hash_table_lookup(printnicks, nick) == NULL) {
			sig_nicklist_new(channel, nick);
			break;
		}
		nick = nick->next;
	}
}

static void i_hash_free_value(void *key, void *value)
{
	g_free(value);
}

void fe_messages_init(void)
{
	printnicks = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);

	settings_add_bool("lookandfeel", "hilight_nick_matches", TRUE);
	settings_add_bool("lookandfeel", "hilight_nick_matches_everywhere", FALSE);
	settings_add_bool("lookandfeel", "emphasis", TRUE);
	settings_add_bool("lookandfeel", "emphasis_replace", FALSE);
	settings_add_bool("lookandfeel", "emphasis_multiword", FALSE);
	settings_add_bool("lookandfeel", "emphasis_italics", FALSE);
	settings_add_bool("lookandfeel", "show_nickmode", TRUE);
	settings_add_bool("lookandfeel", "show_nickmode_empty", TRUE);
	settings_add_bool("lookandfeel", "print_active_channel", FALSE);
	settings_add_bool("lookandfeel", "show_quit_once", FALSE);
	settings_add_bool("lookandfeel", "show_own_nickchange_once", FALSE);
	settings_add_bool("lookandfeel", "away_notify_public", FALSE);
	settings_add_bool("lookandfeel", "show_extended_join", FALSE);
	settings_add_bool("lookandfeel", "show_account_notify", FALSE);

	/* Nick column feature settings */
	settings_add_bool("lookandfeel", "nick_column_enabled", FALSE);
	settings_add_int("lookandfeel", "nick_column_width", 12);

	signal_add_last("message public", (SIGNAL_FUNC) sig_message_public);
	signal_add_last("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add_last("message own_public", (SIGNAL_FUNC) sig_message_own_public);
	signal_add_last("message own_private", (SIGNAL_FUNC) sig_message_own_private);
	signal_add_last("message join", (SIGNAL_FUNC) sig_message_join);
	signal_add_last("message host_changed", (SIGNAL_FUNC) sig_message_host_changed);
	signal_add_last("message account_changed", (SIGNAL_FUNC) sig_message_account_changed);
	signal_add_last("message part", (SIGNAL_FUNC) sig_message_part);
	signal_add_last("message quit", (SIGNAL_FUNC) sig_message_quit);
	signal_add_last("message kick", (SIGNAL_FUNC) sig_message_kick);
	signal_add_last("message nick", (SIGNAL_FUNC) sig_message_nick);
	signal_add_last("message own_nick", (SIGNAL_FUNC) sig_message_own_nick);
	signal_add_last("message invite", (SIGNAL_FUNC) sig_message_invite);
	signal_add_last("message invite_other", (SIGNAL_FUNC) sig_message_invite_other);
	signal_add_last("message topic", (SIGNAL_FUNC) sig_message_topic);
	signal_add_last("message away_notify", (SIGNAL_FUNC) sig_message_away_notify);

	signal_add("nicklist new", (SIGNAL_FUNC) sig_nicklist_new);
	signal_add("nicklist remove", (SIGNAL_FUNC) sig_nicklist_remove);
	signal_add("nicklist changed", (SIGNAL_FUNC) sig_nicklist_changed);
	signal_add("nicklist host changed", (SIGNAL_FUNC) sig_nicklist_new);
	signal_add("channel joined", (SIGNAL_FUNC) sig_channel_joined);
}

void fe_messages_deinit(void)
{
	g_hash_table_foreach(printnicks, (GHFunc) i_hash_free_value, NULL);
	g_hash_table_destroy(printnicks);

	signal_remove("message public", (SIGNAL_FUNC) sig_message_public);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("message own_public", (SIGNAL_FUNC) sig_message_own_public);
	signal_remove("message own_private", (SIGNAL_FUNC) sig_message_own_private);
	signal_remove("message join", (SIGNAL_FUNC) sig_message_join);
	signal_remove("message host_changed", (SIGNAL_FUNC) sig_message_host_changed);
	signal_remove("message account_changed", (SIGNAL_FUNC) sig_message_account_changed);
	signal_remove("message part", (SIGNAL_FUNC) sig_message_part);
	signal_remove("message quit", (SIGNAL_FUNC) sig_message_quit);
	signal_remove("message kick", (SIGNAL_FUNC) sig_message_kick);
	signal_remove("message nick", (SIGNAL_FUNC) sig_message_nick);
	signal_remove("message own_nick", (SIGNAL_FUNC) sig_message_own_nick);
	signal_remove("message invite_other", (SIGNAL_FUNC) sig_message_invite_other);
	signal_remove("message invite", (SIGNAL_FUNC) sig_message_invite);
	signal_remove("message topic", (SIGNAL_FUNC) sig_message_topic);
	signal_remove("message away_notify", (SIGNAL_FUNC) sig_message_away_notify);

	signal_remove("nicklist new", (SIGNAL_FUNC) sig_nicklist_new);
	signal_remove("nicklist remove", (SIGNAL_FUNC) sig_nicklist_remove);
	signal_remove("nicklist changed", (SIGNAL_FUNC) sig_nicklist_changed);
	signal_remove("nicklist host changed", (SIGNAL_FUNC) sig_nicklist_new);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_channel_joined);
}
