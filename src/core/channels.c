/*
 channel.c : irssi

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

#include "channels.h"

typedef CHANNEL_REC *(*CHANNEL_FIND_FUNC)(SERVER_REC *, const char *);

GSList *channels; /* List of all channels */

/* Create a new channel */
CHANNEL_REC *channel_create(int chat_type, SERVER_REC *server,
			    const char *name, int automatic)
{
	CHANNEL_REC *channel;

	g_return_val_if_fail(server == NULL || IS_SERVER(server), NULL);
	g_return_val_if_fail(name != NULL, NULL);

	channel = NULL;
	signal_emit("channel create", 5, &channel, GINT_TO_POINTER(chat_type),
		    server, name, GINT_TO_POINTER(automatic));
	return channel;
}

void channel_init(CHANNEL_REC *channel, int automatic)
{
	g_return_if_fail(channel != NULL);
	g_return_if_fail(channel->name != NULL);

	channels = g_slist_append(channels, channel);
	if (channel->server != NULL) {
		channel->server->channels =
			g_slist_append(channel->server->channels, channel);
	}

        MODULE_DATA_INIT(channel);
	channel->type = module_get_uniq_id_str("WINDOW ITEM TYPE", "CHANNEL");
        channel->mode = g_strdup("");
	channel->createtime = time(NULL);

	signal_emit("channel created", 2, channel, GINT_TO_POINTER(automatic));
}

void channel_destroy(CHANNEL_REC *channel)
{
	g_return_if_fail(IS_CHANNEL(channel));

	if (channel->destroying) return;
	channel->destroying = TRUE;

	channels = g_slist_remove(channels, channel);
	if (channel->server != NULL)
		channel->server->channels = g_slist_remove(channel->server->channels, channel);
	signal_emit("channel destroyed", 1, channel);

        MODULE_DATA_DEINIT(channel);
	g_free_not_null(channel->topic);
	g_free_not_null(channel->key);
	g_free(channel->mode);
	g_free(channel->name);
	g_free(channel);
}

static CHANNEL_REC *channel_find_server(SERVER_REC *server,
					const char *name)
{
	GSList *tmp;

	g_return_val_if_fail(IS_SERVER(server), NULL);

	if (server->channel_find_func != NULL) {
		/* use the server specific channel find function */
		CHANNEL_FIND_FUNC channel_find_func;
		channel_find_func =
			(CHANNEL_FIND_FUNC) server->channel_find_func;
		return channel_find_func(server, name);
	}

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		CHANNEL_REC *rec = tmp->data;

		if (rec->chat_type == server->chat_type &&
		    g_strcasecmp(name, rec->name) == 0)
			return rec;
	}

	return NULL;
}

CHANNEL_REC *channel_find(SERVER_REC *server, const char *name)
{
	g_return_val_if_fail(server == NULL || IS_SERVER(server), NULL);
	g_return_val_if_fail(name != NULL, NULL);

	if (server != NULL)
		return channel_find_server(server, name);

	/* find from any server */
	return gslist_foreach_find(servers,
				   (FOREACH_FIND_FUNC) channel_find_server,
				   (void *) name);
}

void channels_init(void)
{
}

void channels_deinit(void)
{
	module_uniq_destroy("CHANNEL");
}
