/*
 irc-channels.c : irssi

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
#include "signals.h"
#include "misc.h"

#include "bans.h"
#include "irc-channels.h"
#include "channels-setup.h"
#include "irc.h"
#include "modes.h"
#include "levels.h"
#include "mode-lists.h"
#include "irc-nicklist.h"

void channels_query_init(void);
void channels_query_deinit(void);

void channel_events_init(void);
void channel_events_deinit(void);

void channel_rejoin_init(void);
void channel_rejoin_deinit(void);

void massjoin_init(void);
void massjoin_deinit(void);

IRC_CHANNEL_REC *irc_channel_create(IRC_SERVER_REC *server,
				    const char *name, int automatic)
{
	IRC_CHANNEL_REC *rec;

	g_return_val_if_fail(server == NULL || IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(name != NULL, NULL);

	rec = g_new0(IRC_CHANNEL_REC, 1);
	rec->chat_type = module_get_uniq_id("IRC CHANNEL", 0);
	rec->name = g_strdup(name);
	rec->server = server;
	if (*name == '+') rec->no_modes = TRUE;

	channel_init((CHANNEL_REC *) rec, automatic);
	return rec;
}

static void sig_channel_destroyed(IRC_CHANNEL_REC *channel)
{
	if (!IS_IRC_CHANNEL(channel))
                return;

	if (channel->server != NULL && !channel->left && !channel->kicked) {
		/* destroying channel record without actually
		   having left the channel yet */
		irc_send_cmdv(channel->server, "PART %s", channel->name);
	}
}

#define get_join_key(key) \
	(((key) == NULL || *(key) == '\0') ? "x" : (key))

void irc_channels_join(IRC_SERVER_REC *server, const char *data, int automatic)
{
	CHANNEL_SETUP_REC *schannel;
	IRC_CHANNEL_REC *chanrec;
	GString *outchans, *outkeys;
	char *channels, *keys, *key;
	char **chanlist, **keylist, **tmp, **tmpkey, *channel;
	void *free_arg;
	int use_keys;

	g_return_if_fail(data != NULL);
	if (!IS_IRC_SERVER(server) || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST, &channels, &keys))
		return;
	if (*channels == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

        chanlist = g_strsplit(channels, ",", -1);
	keylist = g_strsplit(keys, ",", -1);

	outchans = g_string_new(NULL);
	outkeys = g_string_new(NULL);

	use_keys = *keys != '\0';
	tmpkey = keylist;
	for (tmp = chanlist; *tmp != NULL; tmp++) {
		channel = ischannel(**tmp) ? g_strdup(*tmp) :
			g_strdup_printf("#%s", *tmp);

		chanrec = irc_channel_find(server, channel);
		if (chanrec == NULL) {
			schannel = channels_setup_find(channel, server->connrec->chatnet);

                        g_string_sprintfa(outchans, "%s,", channel);
                        if (*tmpkey != NULL && **tmpkey != '\0')
                        	key = *tmpkey;
                        else if (schannel != NULL && schannel->password != NULL) {
				/* get password from setup record */
                                use_keys = TRUE;
				key = schannel->password;
			} else key = NULL;

			g_string_sprintfa(outkeys, "%s,", get_join_key(key));
			chanrec = irc_channel_create(server, channel + (channel[0] == '!' && channel[1] == '!'), automatic);
			if (key != NULL) chanrec->key = g_strdup(key);
		}
		g_free(channel);

		if (*tmpkey != NULL)
                        tmpkey++;
	}

	if (outchans->len > 0) {
		g_string_truncate(outchans, outchans->len-1);
		g_string_truncate(outkeys, outkeys->len-1);
		irc_send_cmdv(server, use_keys ? "JOIN %s %s" : "JOIN %s",
			      outchans->str, outkeys->str);
	}

	g_string_free(outchans, TRUE);
	g_string_free(outkeys, TRUE);

	g_strfreev(chanlist);
	g_strfreev(keylist);

	cmd_params_free(free_arg);
}

/* function for finding IRC channels - adds support for !channels */
static CHANNEL_REC *irc_channel_find_server(SERVER_REC *server,
					    const char *channel)
{
	GSList *tmp;

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (rec->chat_type != server->channel_type)
                        continue;

		if (g_strcasecmp(channel, rec->name) == 0)
			return rec;

                /* check after removing ABCDE from !ABCDEchannel */
		if (*channel == '!' && *rec->name == '!' &&
		    g_strcasecmp(channel+1, rec->name+6) == 0)
			return rec;
	}

	return NULL;
}

static void sig_connected(SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	server->channel_find_func = (void *) irc_channel_find_server;
	server->channel_type = module_get_uniq_id("IRC CHANNEL", 0);;
}

void irc_channels_init(void)
{
	signal_add("server connected", (SIGNAL_FUNC) sig_connected);

	channel_events_init();
	channel_rejoin_init();
        channels_query_init();
	channels_setup_init();

	bans_init();
        modes_init();
	mode_lists_init();
	massjoin_init();
	irc_nicklist_init();
}

void irc_channels_deinit(void)
{
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);

	channel_events_deinit();
	channel_rejoin_deinit();
        channels_query_deinit();
        channels_setup_deinit();

	bans_deinit();
        modes_deinit();
	mode_lists_deinit();
	massjoin_deinit();
	irc_nicklist_deinit();

	module_uniq_destroy("IRC CHANNEL");
}
