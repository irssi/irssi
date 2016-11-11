/*
 fe-modes.c : irssi

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
#include "module-formats.h"
#include "signals.h"
#include "levels.h"
#include "misc.h"
#include "settings.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "modes.h"
#include "ignore.h"

#include "printtext.h"

#define MODE_WAIT_TIME 3 /* how many seconds to wait for identical modes */

typedef struct {
	IRC_CHANNEL_REC *channel;
	char *mode;
	GSList *nicks;
	time_t last_mode;
} MODE_REC;

static int mode_tag, group_multi_mode;
static GSList *modes;

static MODE_REC *mode_find_channel(IRC_CHANNEL_REC *channel)
{
	GSList *tmp;

	g_return_val_if_fail(channel != NULL, NULL);

	for (tmp = modes; tmp != NULL; tmp = tmp->next) {
		MODE_REC *rec = tmp->data;

		if (rec->channel == channel)
                        return rec;
	}

	return NULL;
}

static void mode_destroy(MODE_REC *mode)
{
	g_return_if_fail(mode != NULL);

	modes = g_slist_remove(modes, mode);
	g_slist_foreach(mode->nicks, (GFunc) g_free, NULL);
	g_slist_free(mode->nicks);
	g_free(mode->mode);
	g_free(mode);
}

static void print_mode(MODE_REC *rec)
{
	GSList *tmp;
	char *nicks;

	if (g_slist_find(channels, rec->channel) == NULL) {
		/* channel was destroyed while we were waiting.. */
		return;
	}

	tmp = modes; modes = NULL;

	if (gslist_is_unique(rec->nicks, (GCompareFunc)g_strcmp0))
		nicks = g_strdup(rec->nicks->data);
	else
		nicks = gslist_to_string(rec->nicks, ", ");
	printformat(rec->channel->server, rec->channel->visible_name,
		    MSGLEVEL_MODES, IRCTXT_CHANMODE_CHANGE,
		    rec->channel->visible_name, rec->mode, nicks, "");
	g_free(nicks);

	modes = tmp;
}

/* something is going to be printed to screen, print our current netsplit
   message before it. */
static void sig_print_starting(void)
{
	while (modes != NULL) {
		print_mode(modes->data);
                mode_destroy(modes->data);
	}

	signal_remove("print starting", sig_print_starting);
}

static int sig_check_modes(void)
{
	GSList *tmp, *next;

	if (modes == NULL)
		return 1;

	for (tmp = modes; tmp != NULL; tmp = next) {
		MODE_REC *rec = tmp->data;

		next = tmp->next;
		if (time(NULL)-rec->last_mode >= MODE_WAIT_TIME) {
			print_mode(rec);
			mode_destroy(rec);
		}
	}

	if (modes == NULL)
		signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
	return 1;
}

static void msg_multi_mode(IRC_CHANNEL_REC *channel, const char *sender,
			   const char *addr, const char *mode)
{
	MODE_REC *rec;

	if (modes == NULL)
		signal_add("print starting", (SIGNAL_FUNC) sig_print_starting);

	rec = mode_find_channel(channel);
	if (rec != NULL && g_strcmp0(rec->mode, mode) != 0) {
		/* different mode than last time, show and remove the old */
		print_mode(rec);
		mode_destroy(rec);
		rec = NULL;
	}

	if (rec == NULL) {
                /* no previous mode, create new */
		rec = g_new0(MODE_REC, 1);
		modes = g_slist_append(modes, rec);

		rec->channel = channel;
		rec->mode = g_strdup(mode);
	}

	rec->nicks = g_slist_append(rec->nicks, g_strdup(sender));
	rec->last_mode = time(NULL);

	signal_stop();
}

/* FIXME: should be moved to fe-irc-messages.c.. */
static void sig_message_mode(IRC_SERVER_REC *server, const char *channel,
			     const char *nick, const char *addr,
			     const char *mode)
{
	if (nick == NULL) nick = server->real_address;

	if (ignore_check(SERVER(server), nick, addr, channel,
			 mode, MSGLEVEL_MODES))
		return;

	if (!server_ischannel(SERVER(server), channel)) {
		/* user mode change */
		printformat(server, NULL, MSGLEVEL_MODES,
			    IRCTXT_USERMODE_CHANGE, mode, channel);
	} else if (addr == NULL) {
		/* channel mode changed by server */
		printformat(server, channel, MSGLEVEL_MODES,
			    IRCTXT_SERVER_CHANMODE_CHANGE,
			    channel, mode, nick);
	} else {
		/* channel mode changed by normal user */
		IRC_CHANNEL_REC *chanrec;

		chanrec = !group_multi_mode ? NULL :
			irc_channel_find(server, channel);

		if (chanrec != NULL && g_ascii_strcasecmp(nick, server->nick) != 0)
			msg_multi_mode(chanrec, nick, addr, mode);
		else {
			printformat(server, channel, MSGLEVEL_MODES,
				    IRCTXT_CHANMODE_CHANGE,
				    channel, mode, nick, addr);
		}
	}
}

static void read_settings(void)
{
	int old_group;

        old_group = group_multi_mode;
	group_multi_mode = settings_get_bool("group_multi_mode");

	if (old_group && !group_multi_mode) {
		g_source_remove(mode_tag);
		mode_tag = -1;
	} else if (!old_group && group_multi_mode) {
		mode_tag = g_timeout_add(1000, (GSourceFunc) sig_check_modes, NULL);
	}
}

void fe_modes_init(void)
{
	settings_add_bool("misc", "group_multi_mode", TRUE);
        mode_tag = -1;

	read_settings();
	signal_add("message irc mode", (SIGNAL_FUNC) sig_message_mode);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void fe_modes_deinit(void)
{
	if (mode_tag != -1)
		g_source_remove(mode_tag);

	signal_remove("message irc mode", (SIGNAL_FUNC) sig_message_mode);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	signal_remove("print starting", (SIGNAL_FUNC) sig_print_starting);
}
