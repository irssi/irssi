/*
 channels.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "modules.h"
#include "misc.h"

#include "bans.h"
#include "channels.h"
#include "channels-setup.h"
#include "irc.h"
#include "modes.h"
#include "levels.h"
#include "mode-lists.h"
#include "nicklist.h"

void channels_query_init(void);
void channels_query_deinit(void);

void channel_events_init(void);
void channel_events_deinit(void);

void channel_rejoin_init(void);
void channel_rejoin_deinit(void);

void massjoin_init(void);
void massjoin_deinit(void);

GSList *channels; /* List of all channels */

CHANNEL_REC *channel_create(IRC_SERVER_REC *server, const char *channel, int automatic)
{
	CHANNEL_REC *rec;

	g_return_val_if_fail(channel != NULL, NULL);

	rec = g_new0(CHANNEL_REC, 1);
	channels = g_slist_append(channels, rec);
	if (server != NULL)
		server->channels = g_slist_append(server->channels, rec);

        MODULE_DATA_INIT(rec);
	rec->type = module_get_uniq_id("IRC", WI_IRC_CHANNEL);
	rec->name = g_strdup(channel);
	rec->server = server;
	rec->createtime = time(NULL);

	if (*channel == '+')
		rec->no_modes = TRUE;

	signal_emit("channel created", 2, rec, GINT_TO_POINTER(automatic));

	return rec;
}

void channel_destroy(CHANNEL_REC *channel)
{
	g_return_if_fail(channel != NULL);

	if (channel->destroying) return;
	channel->destroying = TRUE;

	channels = g_slist_remove(channels, channel);
	if (channel->server != NULL)
		channel->server->channels = g_slist_remove(channel->server->channels, channel);
	signal_emit("channel destroyed", 1, channel);

	if (channel->server != NULL && !channel->left && !channel->kicked) {
		/* destroying channel record without actually left the channel yet */
		irc_send_cmdv(channel->server, "PART %s", channel->name);
	}

        MODULE_DATA_DEINIT(channel);
	g_free_not_null(channel->topic);
	g_free_not_null(channel->key);
	g_free(channel->name);
	g_free(channel);
}

static CHANNEL_REC *channel_find_server(IRC_SERVER_REC *server, const char *channel)
{
	GSList *tmp;

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (g_strcasecmp(channel, rec->name) == 0)
			return rec;

                /* check after removing ABCDE from !ABCDEchannel */
		if (*channel == '!' && *rec->name == '!' &&
		    g_strcasecmp(channel+1, rec->name+6) == 0)
			return rec;
	}

	return NULL;
}

CHANNEL_REC *channel_find(IRC_SERVER_REC *server, const char *channel)
{
	g_return_val_if_fail(channel != NULL, NULL);

	if (server != NULL)
		return channel_find_server(server, channel);

	/* find from any server */
	return gslist_foreach_find(servers, (FOREACH_FIND_FUNC) channel_find_server, (void *) channel);
}


char *channel_get_mode(CHANNEL_REC *channel)
{
	GString *mode;
	char *ret;

	g_return_val_if_fail(channel != NULL, NULL);

	mode = g_string_new(NULL);

	if (channel->mode_secret) g_string_append_c(mode, 's');
	if (channel->mode_private) g_string_append_c(mode, 'p');
	if (channel->mode_moderate) g_string_append_c(mode, 'm');
	if (channel->mode_invite) g_string_append_c(mode, 'i');
	if (channel->mode_nomsgs) g_string_append_c(mode, 'n');
	if (channel->mode_optopic) g_string_append_c(mode, 't');
	if (channel->mode_anonymous) g_string_append_c(mode, 'a');
	if (channel->mode_reop) g_string_append_c(mode, 'r');
	if (channel->mode_key) g_string_append_c(mode, 'k');
	if (channel->limit > 0) g_string_append_c(mode, 'l');

	if (channel->mode_key) g_string_sprintfa(mode, " %s", channel->key);
	if (channel->limit > 0) g_string_sprintfa(mode, " %d", channel->limit);

	ret = mode->str;
	g_string_free(mode, FALSE);
	return ret;
}

#define get_join_key(key) \
	(((key) == NULL || *(key) == '\0') ? "x" : (key))

void channels_join(IRC_SERVER_REC *server, const char *data, int automatic)
{
	SETUP_CHANNEL_REC *schannel;
	CHANNEL_REC *chanrec;
	GString *outchans, *outkeys;
	char *channels, *keys, *key;
	char **chanlist, **keylist, **tmp, **tmpkey, *channel;
	void *free_arg;
	int use_keys;

	g_return_if_fail(data != NULL);
	if (server == NULL || !server->connected || !irc_server_check(server))
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

		chanrec = channel_find(server, channel);
		if (chanrec == NULL) {
			schannel = channels_setup_find(channel, server->connrec->ircnet);

                        g_string_sprintfa(outchans, "%s,", channel);
			if (schannel == NULL || schannel->password == NULL) {
				key = *tmpkey == NULL || **tmpkey == '\0' ? NULL : *tmpkey;
			} else {
				/* get password from setup record */
                                use_keys = TRUE;
				key = schannel->password;
			}

			g_string_sprintfa(outkeys, "%s,", get_join_key(key));
			chanrec = channel_create(server, channel + (channel[0] == '!' && channel[1] == '!'), automatic);
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

void channels_init(void)
{
	channel_events_init();
	channel_rejoin_init();
        channels_query_init();
	channels_setup_init();

	bans_init();
        modes_init();
	mode_lists_init();
	massjoin_init();
	nicklist_init();
}

void channels_deinit(void)
{
	channel_events_deinit();
	channel_rejoin_deinit();
        channels_query_deinit();
        channels_setup_deinit();

	bans_deinit();
        modes_deinit();
	mode_lists_deinit();
	massjoin_deinit();
	nicklist_deinit();
}
