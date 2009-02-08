/*
 channel-rejoin.c : rejoin to channel if it's "temporarily unavailable"
                    this has nothing to do with autorejoin if kicked

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
#include "signals.h"
#include "settings.h"
#include "misc.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-commands.h"
#include "channel-rejoin.h"

#define REJOIN_TIMEOUT (1000*60*5) /* try to rejoin every 5 minutes */

static int rejoin_tag;

static void rejoin_destroy(IRC_SERVER_REC *server, REJOIN_REC *rec)
{
	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(rec != NULL);

	server->rejoin_channels =
		g_slist_remove(server->rejoin_channels, rec);

	signal_emit("channel rejoin remove", 2, server, rec);

	g_free(rec->channel);
	g_free_not_null(rec->key);
	g_free(rec);
}

static REJOIN_REC *rejoin_find(IRC_SERVER_REC *server, const char *channel)
{
	GSList *tmp;

	g_return_val_if_fail(IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(channel != NULL, NULL);

	for (tmp = server->rejoin_channels; tmp != NULL; tmp = tmp->next) {
                REJOIN_REC *rec = tmp->data;

		if (g_strcasecmp(rec->channel, channel) == 0)
                        return rec;
	}

	return NULL;
}

#define channel_have_key(chan) \
	((chan) != NULL && (chan)->key != NULL && (chan)->key[0] != '\0')

static int channel_rejoin(IRC_SERVER_REC *server, const char *channel)
{
	IRC_CHANNEL_REC *chanrec;
	REJOIN_REC *rec;

	g_return_val_if_fail(IS_IRC_SERVER(server), 0);
	g_return_val_if_fail(channel != NULL, 0);

	chanrec = irc_channel_find(server, channel);
	if (chanrec == NULL || chanrec->joined) return 0;

	if (!settings_get_bool("channels_rejoin_unavailable")) {
		chanrec->left = TRUE;
		channel_destroy(CHANNEL(chanrec));
		return 0;
	}
	
	rec = rejoin_find(server, channel);
	if (rec != NULL) {
		/* already exists */
		rec->joining = FALSE;

		/* update channel key */
		g_free_and_null(rec->key);
		if (channel_have_key(chanrec))
			rec->key = g_strdup(chanrec->key);
	} else {
		/* new rejoin */
		rec = g_new0(REJOIN_REC, 1);
		rec->channel = g_strdup(channel);
		if (channel_have_key(chanrec))
			rec->key = g_strdup(chanrec->key);

		server->rejoin_channels =
			g_slist_append(server->rejoin_channels, rec);
		signal_emit("channel rejoin new", 2, server, rec);
	}

	chanrec->left = TRUE;
	channel_destroy(CHANNEL(chanrec));
	return 1;
}

static void event_duplicate_channel(IRC_SERVER_REC *server, const char *data)
{
	CHANNEL_REC *chanrec;
	char *params, *channel, *p;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 3, NULL, NULL, &channel);
	p = strchr(channel, ' ');
	if (p != NULL) *p = '\0';

	if (channel[0] == '!' && channel[1] != '!') {
		chanrec = channel_find(SERVER(server), channel);
		if (chanrec != NULL && !chanrec->names_got) {
			/* duplicate channel - this should only happen when
			   there's some sync problem with servers, rejoining
			   after a while should help.

			   note that this same 407 is sent when trying to
			   create !!channel that already exists so we don't
			   want to try rejoining then. */
			if (channel_rejoin(server, channel)) {
				signal_stop();
			}
		}
	}

	g_free(params);
}

static void event_target_unavailable(IRC_SERVER_REC *server, const char *data)
{
	char *params, *channel;
	IRC_CHANNEL_REC *chanrec;

	g_return_if_fail(data != NULL);

	params = event_get_params(data, 2, NULL, &channel);
	if (ischannel(*channel)) {
		chanrec = irc_channel_find(server, channel);
		if (chanrec != NULL && chanrec->joined) {
			/* dalnet event - can't change nick while
			   banned in channel */
		} else {
			/* channel is unavailable - try to join again
			   a bit later */
			if (channel_rejoin(server, channel)) {
				signal_stop();
			}
		}
	}

	g_free(params);
}

/* join ok/failed - remove from rejoins list. this happens always after join
   except if the "target unavailable" error happens again */
static void sig_remove_rejoin(IRC_CHANNEL_REC *channel)
{
	REJOIN_REC *rec;

	if (!IS_IRC_CHANNEL(channel))
		return;

	rec = rejoin_find(channel->server, channel->name);
	if (rec != NULL && rec->joining) {
		/* join failed, remove the rejoin */
		rejoin_destroy(channel->server, rec);
	}
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	while (server->rejoin_channels != NULL)
		rejoin_destroy(server, server->rejoin_channels->data);
}

static void server_rejoin_channels(IRC_SERVER_REC *server)
{
	GSList *tmp, *next;
	GString *channels, *keys;
	int use_keys;

	g_return_if_fail(IS_IRC_SERVER(server));

	channels = g_string_new(NULL);
	keys = g_string_new(NULL);

        use_keys = FALSE;
	for (tmp = server->rejoin_channels; tmp != NULL; tmp = next) {
		REJOIN_REC *rec = tmp->data;
		next = tmp->next;

		if (rec->joining) {
			/* we missed the join (failed) message,
			   remove from rejoins.. */
			rejoin_destroy(server, rec);
			continue;
		}

		rec->joining = TRUE;
		g_string_append_printf(channels, "%s,", rec->channel);
		if (rec->key == NULL)
			g_string_append(keys, "x,");
		else {
			g_string_append_printf(keys, "%s,", rec->key);
                        use_keys = TRUE;
		}
	}

	if (channels->len > 0) {
                g_string_truncate(channels, channels->len-1);
                g_string_truncate(keys, keys->len-1);

		if (use_keys) g_string_append_printf(channels, " %s", keys->str);
		server->channels_join(SERVER(server), channels->str, TRUE);
	}

	g_string_free(channels, TRUE);
	g_string_free(keys, TRUE);
}

static int sig_rejoin(void)
{
	GSList *tmp;

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		IRC_SERVER_REC *rec = tmp->data;

		if (IS_IRC_SERVER(rec) && rec->rejoin_channels != NULL)
			server_rejoin_channels(rec);
	}

	return TRUE;
}

static void cmd_rmrejoins(const char *data, IRC_SERVER_REC *server)
{
        CMD_IRC_SERVER(server);

	while (server->rejoin_channels != NULL)
		rejoin_destroy(server, server->rejoin_channels->data);
}

void channel_rejoin_init(void)
{
	settings_add_bool("servers", "channels_rejoin_unavailable", TRUE);

	rejoin_tag = g_timeout_add(REJOIN_TIMEOUT,
				   (GSourceFunc) sig_rejoin, NULL);

	command_bind_irc("rmrejoins", NULL, (SIGNAL_FUNC) cmd_rmrejoins);
	signal_add_first("event 407", (SIGNAL_FUNC) event_duplicate_channel);
	signal_add_first("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_add_first("channel joined", (SIGNAL_FUNC) sig_remove_rejoin);
	signal_add_first("channel destroyed", (SIGNAL_FUNC) sig_remove_rejoin);
	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}

void channel_rejoin_deinit(void)
{
	g_source_remove(rejoin_tag);

	command_unbind("rmrejoins", (SIGNAL_FUNC) cmd_rmrejoins);
	signal_remove("event 407", (SIGNAL_FUNC) event_duplicate_channel);
	signal_remove("event 437", (SIGNAL_FUNC) event_target_unavailable);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_remove_rejoin);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_remove_rejoin);
	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}
