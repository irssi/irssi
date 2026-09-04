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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/channels-setup.h>

#include <irssi/src/irc/core/bans.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/irc/core/mode-lists.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-nicklist.h>
#include <irssi/src/irc/core/channel-rejoin.h>

void channels_query_init(void);
void channels_query_deinit(void);

void channel_events_init(void);
void channel_events_deinit(void);

void irc_channels_setup_init(void);
void irc_channels_setup_deinit(void);

void massjoin_init(void);
void massjoin_deinit(void);

IRC_CHANNEL_REC *irc_channel_create(IRC_SERVER_REC *server, const char *name,
				    const char *visible_name, int automatic)
{
	IRC_CHANNEL_REC *rec;

	g_return_val_if_fail(server == NULL || IS_IRC_SERVER(server), NULL);
	g_return_val_if_fail(name != NULL, NULL);

	rec = g_new0(IRC_CHANNEL_REC, 1);
	if (*name == '+') rec->no_modes = TRUE;

	channel_init((CHANNEL_REC *) rec, (SERVER_REC *) server,
		     name, visible_name, automatic);
	return rec;
}

#define get_join_key(key) \
	(((key) == NULL || *(key) == '\0') ? "x" : (key))

static char *force_channel_name(IRC_SERVER_REC *server, const char *name)
{
	char *chantypes;

	if (server_ischannel(SERVER(server), name))
		return g_strdup(name);

	chantypes = g_hash_table_lookup(server->isupport, "chantypes");
	if (chantypes == NULL || *chantypes == '\0' || strchr(chantypes, '#') != NULL)
		chantypes = "#";

	return g_strdup_printf("%c%s", *chantypes, name);
}

static void irc_channels_send_joins(IRC_SERVER_REC *server,
									GString *outchans, GString *outkeys,
									int use_keys)
{
	if (use_keys)
		irc_send_cmdv(IRC_SERVER(server), "JOIN %s %s", outchans->str, outkeys->str);
	else
		irc_send_cmdv(IRC_SERVER(server), "JOIN %s", outchans->str);

	g_string_truncate(outchans, 0);
	g_string_truncate(outkeys, 0);
}

static void irc_channels_join(IRC_SERVER_REC *server, const char *data,
			      int automatic)
{
	CHANNEL_SETUP_REC *schannel;
	IRC_CHANNEL_REC *chanrec;
	GString *outchans, *outkeys;
	GPtrArray *channel_list, *key_list;
	char* my_channel;
	char* my_key;
	unsigned int i;
	char *channels, *keys, *key, *space;
	char **chanlist, **keylist, **tmp, **tmpkey, *channel, *channame;
	void *free_arg;
	int use_keys, cmdlen;

	g_return_if_fail(data != NULL);
	g_return_if_fail(IS_IRC_SERVER(server) && server->connected);
	if (*data == '\0') return;

	if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_GETREST,
			    &channels, &keys))
		return;

	/* keys shouldn't contain space */
	space = strchr(keys, ' ');
	if (space != NULL) {
		*space = '\0';
	}

	chanlist = g_strsplit(channels, ",", -1);
	keylist = g_strsplit(keys, ",", -1);

	outchans = g_string_new(NULL);
	outkeys = g_string_new(NULL);

	use_keys = *keys != '\0';
	tmpkey = keylist;

	channel_list = g_ptr_array_new();
	key_list = g_ptr_array_new();

	for (tmp = chanlist; *tmp != NULL; tmp++) {
		channel = force_channel_name(server, *tmp);
		chanrec = irc_channel_find(server, channel);

		if (chanrec == NULL) {
			schannel = channel_setup_find(channel, server->connrec->chatnet);

			if (*tmpkey != NULL && **tmpkey != '\0')
				key = *tmpkey;
			else if (schannel != NULL && schannel->password != NULL) {
				/* get password from setup record */
				use_keys = TRUE;
				key = schannel->password;
			} else {
				key = NULL;
			}

			channame = channel + (channel[0] == '!' && channel[1] == '!');
			g_ptr_array_add(channel_list, g_strdup(channame));
			g_ptr_array_add(key_list, g_strdup(get_join_key(key)));

			chanrec = irc_channel_create(server, channame, NULL,
							     automatic);
			if (key != NULL)
				chanrec->key = g_strdup(key);
		}
		g_free(channel);

		if (*tmpkey != NULL)
			tmpkey++;
	}

	g_assert(channel_list->len == key_list->len);

	for (i = 0; i < channel_list->len ; i++) {
		my_channel = g_ptr_array_index(channel_list, i);
		my_key = g_ptr_array_index(key_list, i);

		/* How long is the pending queue? */
		cmdlen = outchans->len + outkeys->len;
		cmdlen += 5; /* "JOIN " */
		cmdlen += 1; /* "," */

		/* Need to see if we're too big when we add the pending bits too. */
		cmdlen += server_ischannel(SERVER(server), my_channel) ? strlen(my_channel) :
					strlen(my_channel)+1;
		cmdlen += strlen(my_key);

		if (cmdlen > server->max_message_len - 5) {
			/* Send what we have so far. */
			irc_channels_send_joins(server, outchans, outkeys, use_keys);
		}

		g_string_append_printf(outchans, "%s,", my_channel);
		g_string_append_printf(outkeys, "%s,", my_key);
	}

	/* Flush out anything left at the end too. */
	if (outchans->len != 0)
		irc_channels_send_joins(server, outchans, outkeys, use_keys);

	g_string_free(outchans, TRUE);
	g_string_free(outkeys, TRUE);
	g_ptr_array_free(channel_list, TRUE);
	g_ptr_array_free(key_list, TRUE);

	g_strfreev(chanlist);
	g_strfreev(keylist);

	cmd_params_free(free_arg);
}

/* function for finding IRC channels - adds support for !channels */
static CHANNEL_REC *irc_channel_find_server(IRC_SERVER_REC *server, const char *channel)
{
	GSList *tmp;
	char *fmt_channel;

	/* if 'channel' has no leading # this lookup is going to fail, add a
	 * octothorpe in front of it to handle this case. */
	fmt_channel = force_channel_name(server, channel);

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (rec->chat_type != server->chat_type)
                        continue;

		/* check both !ABCDEchannel and !channel */
		if (server->nick_comp_func(fmt_channel, rec->name) == 0) {
			g_free(fmt_channel);
			return rec;
		}

		if (server->nick_comp_func(fmt_channel, rec->visible_name) == 0) {
			g_free(fmt_channel);
			return rec;
		}
	}

	g_free(fmt_channel);

	return NULL;
}

static void sig_server_connected(SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
		return;

	server->channel_find_func =
	    (CHANNEL_REC * (*) (SERVER_REC *, const char *) ) irc_channel_find_server;
	server->channels_join = (void (*) (SERVER_REC *, const char *, int))
		irc_channels_join;
}

static char *irc_get_join_data(CHANNEL_REC *channel)
{
	IRC_CHANNEL_REC *irc_channel = (IRC_CHANNEL_REC *) channel;

	return irc_channel->key == NULL ? g_strdup(irc_channel->name) :
                g_strconcat(irc_channel->name, " ", irc_channel->key, NULL);
}

static void sig_channel_created(IRC_CHANNEL_REC *channel)
{
	if (IS_IRC_CHANNEL(channel))
                channel->get_join_data = irc_get_join_data;
}

static void sig_channel_destroyed(IRC_CHANNEL_REC *channel)
{
	if (!IS_IRC_CHANNEL(channel))
                return;

	if (!channel->server->disconnected && !channel->left && !channel->kicked) {
		/* destroying channel record without actually
		   having left the channel yet */
		signal_emit("command part", 3, "", channel->server, channel);
	}
}

void irc_channels_init(void)
{
	signal_add_first("server connected", (SIGNAL_FUNC) sig_server_connected);
	signal_add("channel created", (SIGNAL_FUNC) sig_channel_created);
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	channel_events_init();
	channel_rejoin_init(); /* after channel_events_init() */
        channels_query_init();
	irc_channels_setup_init();

	bans_init();
        modes_init();
	mode_lists_init();
	massjoin_init();
	irc_nicklist_init();
}

void irc_channels_deinit(void)
{
	signal_remove("server connected", (SIGNAL_FUNC) sig_server_connected);
	signal_remove("channel created", (SIGNAL_FUNC) sig_channel_created);
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);

	channel_events_deinit();
	channel_rejoin_deinit();
        channels_query_deinit();
        irc_channels_setup_deinit();

	bans_deinit();
        modes_deinit();
	mode_lists_deinit();
	massjoin_deinit();
	irc_nicklist_deinit();
}
