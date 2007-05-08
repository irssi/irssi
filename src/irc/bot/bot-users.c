/*
 bot-users.c : IRC bot plugin for irssi - user handling

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

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE /* for crypt() */
#endif

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "lib-config/iconfig.h"

#include "irc.h"
#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-nicklist.h"
#include "masks.h"

#include "bot-users.h"

#define WRITE_USERS_INTERVAL (60*15)

static char *user_flags = "oavm"; /* Keep these in the same order as USER_xxx flags */

static CONFIG_REC *userconfig;
static GHashTable *users;

static int writeusers_tag;
static time_t last_write;

int botuser_flags2value(const char *flags)
{
	char *pos;
	int val;

	g_return_val_if_fail(flags != NULL, 0);

	val = 0;
	while (*flags != '\0') {
		pos = strchr(user_flags, *flags);
		if (pos != NULL)
			val |= 1 << (int) (pos-user_flags);
		flags++;
	}

	return val;
}

char *botuser_value2flags(int value)
{
	char *str, *p;
	int n;

	p = str = g_malloc(USER_FLAG_COUNT+1);
	for (n = 0; n < USER_FLAG_COUNT; n++) {
		if (value & (1 << n))
			*p++ = user_flags[n];
	}
	*p = '\0';

	return str;
}

/* save channel specific user record */
static void botuser_save_chan(const char *key, USER_CHAN_REC *rec, CONFIG_NODE *node)
{
	CONFIG_NODE *noderec;
	char *str;

	if (rec->flags == 0) {
                /* no flags in this channel - no need to save to config */
		config_node_set_str(userconfig, node, rec->channel, NULL);
		return;
	}

	noderec = config_node_section(node, rec->channel, NODE_TYPE_BLOCK);

	str = botuser_value2flags(rec->flags);
	config_node_set_str(userconfig, noderec, "flags", str);
	g_free_not_null(str);
}

static void botuser_config_save(USER_REC *user)
{
	CONFIG_NODE *node, *subnode, *noderec;
	GSList *tmp;
	char *str;

	user->last_modify = time(NULL);

	node = config_node_traverse(userconfig, "users", TRUE);
	node = config_node_section(node, user->nick, NODE_TYPE_BLOCK);

	str = user->flags == 0 ? NULL :
		botuser_value2flags(user->flags);
	config_node_set_str(userconfig, node, "flags", str);
	g_free_not_null(str);

	config_node_set_str(userconfig, node, "password", user->password);
	config_node_set_int(userconfig, node, "last_modify", (int) user->last_modify);

	/* Save masks */
	if (user->masks == NULL)
		config_node_set_str(userconfig, node, "masks", NULL);
	else {
		subnode = config_node_section(node, "masks", NODE_TYPE_LIST);

		for (tmp = user->masks; tmp != NULL; tmp = tmp->next) {
			USER_MASK_REC *rec = tmp->data;

                        noderec = config_node_section(subnode, NULL, NODE_TYPE_BLOCK);
			config_node_set_str(userconfig, noderec, "mask", rec->mask);

			str = user->flags == 0 ? NULL :
				botuser_value2flags(rec->not_flags);
			config_node_set_str(userconfig, noderec, "not_flags", str);
			g_free_not_null(str);
		}
	}

	/* Save channels */
	if (g_hash_table_size(user->channels) == 0)
		config_node_set_str(userconfig, node, "channels", NULL);
	else {
		subnode = config_node_section(node, "channels", NODE_TYPE_LIST);
		g_hash_table_foreach(user->channels, (GHFunc) botuser_save_chan, subnode);
	}
}

static int botuser_find_mask(USER_REC *user, const char *nick, const char *host)
{
	GSList *tmp;

	g_return_val_if_fail(user != NULL, FALSE);
	g_return_val_if_fail(nick != NULL, FALSE);
	g_return_val_if_fail(host != NULL, FALSE);

	/* Check that masks match */
	for (tmp = user->masks; tmp != NULL; tmp = tmp->next) {
		USER_MASK_REC *rec = tmp->data;

		if (mask_match_address(NULL, rec->mask, nick, host)) {
			user->not_flags = rec->not_flags;
			return TRUE;
		}
	}

	return FALSE;
}

static USER_MASK_REC *botuser_find_full_mask(USER_REC *user, const char *mask)
{
	GSList *tmp;

	g_return_val_if_fail(user != NULL, FALSE);
	g_return_val_if_fail(mask != NULL, FALSE);

	for (tmp = user->masks; tmp != NULL; tmp = tmp->next) {
		USER_MASK_REC *rec = tmp->data;

		if (g_strcasecmp(rec->mask, mask) == 0)
			return rec;
	}

	return NULL;
}

static void botuser_getusers_hash(void *key, USER_REC *user, GList **list)
{
	*list = g_list_append(*list, user);
}

USER_REC *botuser_find(const char *nick, const char *host)
{
	USER_REC *user;
	char *stripnick;
	GList *list, *tmp;

	g_return_val_if_fail(nick != NULL, NULL);

	/* First check for user with same nick */
	stripnick = irc_nick_strip(nick);
	user = g_hash_table_lookup(users, stripnick);
	g_free(stripnick);

	if (user != NULL && host != NULL &&
	    !botuser_find_mask(user, nick, host)) {
		/* mask didn't match, check for more.. */
		user = NULL;
	}

	if (user != NULL || host == NULL)
		return user;

	/* Check for different nicks.. */
	list = NULL;
	g_hash_table_foreach(users, (GHFunc) botuser_getusers_hash, &list);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		if (botuser_find_mask(tmp->data, nick, host)) {
			user = tmp->data;
			break;
		}
	}
	g_list_free(list);

	return user;
}

USER_REC *botuser_find_rec(CHANNEL_REC *channel, NICK_REC *nick)
{
	USER_REC *user, *rec;
	USER_CHAN_REC *userchan;
	GList *list, *tmp;

	g_return_val_if_fail(channel != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	user = NULL; list = NULL;
	g_hash_table_foreach(users, (GHFunc) botuser_getusers_hash, &list);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		userchan = g_hash_table_lookup(rec->channels, channel->name);
		if (userchan != NULL && userchan->nickrec == nick) {
			user = rec;
			break;
		}
	}
	g_list_free(list);

	return user;
}

USER_CHAN_REC *botuser_get_channel(USER_REC *user, const char *channel)
{
	USER_CHAN_REC *rec;

	g_return_val_if_fail(user != NULL, NULL);
	g_return_val_if_fail(channel != NULL, NULL);

	rec = g_hash_table_lookup(user->channels, channel);
	if (rec != NULL) return rec;

	rec = g_new0(USER_CHAN_REC, 1);
	rec->channel = g_strdup(channel);
	g_hash_table_insert(user->channels, rec->channel, rec);
	return rec;
}

USER_REC *botuser_add(const char *nick)
{
	USER_REC *user;

	/* Add new user */
	user = g_new0(USER_REC, 1);
	user->nick = g_strdup(nick);
	g_hash_table_insert(users, user->nick, user);

	botuser_config_save(user);
	return user;
}

void botuser_set_flags(USER_REC *user, int flags)
{
	user->flags = flags;
	botuser_config_save(user);
}

void botuser_set_channel_flags(USER_REC *user, const char *channel, int flags)
{
	USER_CHAN_REC *rec;

	rec = botuser_get_channel(user, channel);
	if (rec != NULL) rec->flags = flags;

	botuser_config_save(user);
}

static USER_MASK_REC *botuser_create_mask(USER_REC *user, const char *mask)
{
	USER_MASK_REC *rec;

	rec = g_new0(USER_MASK_REC, 1);
	rec->mask = g_strdup(mask);

	user->masks = g_slist_append(user->masks, rec);
	return rec;
}

USER_MASK_REC *botuser_add_mask(USER_REC *user, const char *mask)
{
	USER_MASK_REC *rec;

	rec = botuser_create_mask(user, mask);
	botuser_config_save(user);
	return rec;
}

void botuser_set_mask_notflags(USER_REC *user, const char *mask, int not_flags)
{
	USER_MASK_REC *rec;

	rec = botuser_find_full_mask(user, mask);
	if (rec == NULL) rec = botuser_create_mask(user, mask);

	rec->not_flags = not_flags;
	botuser_config_save(user);
}

void botuser_set_password(USER_REC *user, const char *password)
{
	char *pass, salt[3];

	g_return_if_fail(user != NULL);
	g_return_if_fail(password != NULL);

	salt[0] = rand()%20 + 'A';
	salt[1] = rand()%20 + 'A';
	salt[2] = '\0';
	pass = crypt(password, salt);

	if (user->password != NULL) g_free(user->password);
	user->password = g_strdup(pass);
	botuser_config_save(user);
}

int botuser_verify_password(USER_REC *user, const char *password)
{
	char *pass, salt[3];

	g_return_val_if_fail(user != NULL, FALSE);
	g_return_val_if_fail(password != NULL, FALSE);

	if (user->password == NULL || strlen(user->password) < 3)
		return FALSE;

	salt[0] = user->password[0];
	salt[1] = user->password[1];
	salt[2] = '\0';
	pass = crypt(password, salt);
	return strcmp(user->password, pass) == 0;
}

void botuser_save(const char *fname)
{
	config_write(userconfig, fname, 0600);
}

static void event_massjoin(CHANNEL_REC *channel, GSList *nicks)
{
	USER_REC *user;
	USER_CHAN_REC *userchan;
	GSList *users;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(nicks != NULL);

	users = NULL;
	for (; nicks != NULL; nicks = nicks->next) {
		NICK_REC *rec = nicks->data;

		user = botuser_find(rec->nick, rec->host);
		if (user != NULL) {
			userchan = botuser_get_channel(user, channel->name);
			userchan->nickrec = rec;
			users = g_slist_append(users, user);
		}
	}

	if (users != NULL) {
		signal_emit("bot massjoin", 2, channel, users);
		g_slist_free(users);
	}
}

/* channel synced - find everyone's NICK_REC's */
static void sig_channel_sync(CHANNEL_REC *channel)
{
	USER_REC *user;
	USER_CHAN_REC *userchan;
	GSList *tmp, *nicks;

	g_return_if_fail(channel != NULL);

	nicks = nicklist_getnicks(channel);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next) {
		NICK_REC *rec = tmp->data;

		if (rec->send_massjoin)
			continue; /* This will be checked in "massjoin" signal */

		user = botuser_find(rec->nick, rec->host);
		if (user != NULL) {
			userchan = botuser_get_channel(user, channel->name);
			userchan->nickrec = rec;
		}
	}
	g_slist_free(nicks);
}

/* user left channel - remove from users record */
static void sig_nicklist_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	USER_REC *user;
	USER_CHAN_REC *userchan;

	g_return_if_fail(channel != NULL);
	g_return_if_fail(nick != NULL);

	user = botuser_find_rec(channel, nick);
	userchan = user == NULL ? NULL :
		g_hash_table_lookup(user->channels, channel->name);
	if (userchan != NULL) userchan->nickrec = NULL;
}

/* Free memory used by user channel record */
static void user_destroy_chan(const char *key, USER_CHAN_REC *rec)
{
	g_free(rec->channel);
	g_free(rec);
}

static void usermask_destroy(USER_MASK_REC *rec)
{
	g_free(rec->mask);
	g_free(rec);
}

/* Free memory used by user record */
static void user_destroy(const char *key, USER_REC *user)
{
	g_slist_foreach(user->masks, (GFunc) usermask_destroy, NULL);
	g_slist_free(user->masks);

	g_hash_table_foreach(user->channels, (GHFunc) user_destroy_chan, NULL);
	g_hash_table_destroy(user->channels);

	g_free_not_null(user->password);
	g_free(user->nick);
	g_free(user);
}

static int sig_write_users(void)
{
	if (last_write + WRITE_USERS_INTERVAL <= time(NULL)) {
		last_write = time(NULL);
		config_write(userconfig, NULL, -1);
	}
	return 1;
}

static void botuser_config_read_user(CONFIG_NODE *node)
{
	USER_REC *user;
	USER_CHAN_REC *userchan;
	USER_MASK_REC *usermask;
	CONFIG_NODE *subnode;
	GSList *tmp;
	char *value;

	g_return_if_fail(node != NULL);

	/* nick = { ... } */
	if (node->key == NULL || node->value == NULL)
		return;

	/* Add new user */
	user = g_new0(USER_REC, 1);
	user->nick = g_strdup(node->key);
	g_hash_table_insert(users, user->nick, user);

	/* password, flags, modify time */
	user->password = g_strdup(config_node_get_str(node, "password", NULL));
	user->flags = botuser_flags2value(config_node_get_str(node, "flags", ""));
	user->last_modify = (time_t) config_node_get_int(node, "last_modify", 0);

	/* get masks */
        user->masks = NULL;
	subnode = config_node_section(node, "masks", -1);
	tmp = subnode == NULL ? NULL : subnode->value;
	for (; tmp != NULL; tmp = tmp->next) {
		subnode = tmp->data;

		value = config_node_get_str(subnode, "mask", NULL);
		if (value == NULL) continue; /* mask is required */

		usermask = botuser_create_mask(user, value);
		value = config_node_get_str(subnode, "not_flags", "");
		usermask->not_flags = botuser_flags2value(value);
	}

	/* get channels - must be last, messes up pvalue */
	user->channels = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	subnode = config_node_section(node, "channels", -1);
	tmp = subnode == NULL ? NULL : subnode->value;
	for (; tmp != NULL; tmp = tmp->next) {
		subnode = tmp->data;

		value = config_node_get_str(subnode, "channel", NULL);
		if (value == NULL) continue; /* channel is required */

		/* create user channel specific record */
		userchan = g_new0(USER_CHAN_REC, 1);
		userchan->channel = g_strdup(value);
		g_hash_table_insert(user->channels, userchan->channel, userchan);

		value = config_node_get_str(subnode, "flags", "");
		userchan->flags = botuser_flags2value(value);
	}
}

static void botuser_config_read(void)
{
	CONFIG_NODE *node;
	GSList *tmp;
	char *fname;

	/* Read users from ~/.irssi/users */
	fname = g_strdup_printf("%s/users", get_irssi_dir());
	userconfig = config_open(fname, 0600);
	g_free(fname);

	if (userconfig == NULL)
		return; /* access denied?! */

	config_parse(userconfig);

	node = config_node_traverse(userconfig, "users", FALSE);
	tmp = node == NULL ? NULL : node->value;
	for (; tmp != NULL; tmp = tmp->next)
		botuser_config_read_user(tmp->data);
}

void bot_users_init(void)
{
	users = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);

	last_write = time(NULL);
	writeusers_tag = g_timeout_add(10000, (GSourceFunc) sig_write_users, NULL);

	botuser_config_read();
	signal_add_last("massjoin", (SIGNAL_FUNC) event_massjoin);
	signal_add_last("channel sync", (SIGNAL_FUNC) sig_channel_sync);
	signal_add_last("nicklist remove", (SIGNAL_FUNC) sig_nicklist_remove);
}

void bot_users_deinit(void)
{
	if (userconfig != NULL) {
		config_write(userconfig, NULL, -1);
		config_close(userconfig);
	}

	g_source_remove(writeusers_tag);

	g_hash_table_foreach(users, (GHFunc) user_destroy, NULL);
	g_hash_table_destroy(users);

	signal_remove("massjoin", (SIGNAL_FUNC) event_massjoin);
	signal_remove("channel sync", (SIGNAL_FUNC) sig_channel_sync);
	signal_remove("nicklist remove", (SIGNAL_FUNC) sig_nicklist_remove);
}
