/*
 perl-common.c : irssi

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

#define NEED_PERL_H
#define PERL_NO_GET_CONTEXT
#include "module.h"
#include <irssi/src/core/modules.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/core.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/settings.h>

#include <irssi/src/core/commands.h>
#include <irssi/src/core/ignore.h>
#include <irssi/src/core/log.h>
#include <irssi/src/core/rawlog.h>
#include <irssi/src/core/servers-reconnect.h>

#include <irssi/src/core/window-item-def.h>
#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/nicklist.h>

#include <irssi/src/perl/perl-core.h>
#include <irssi/src/perl/perl-common.h>

typedef struct {
	char *stash;
        PERL_OBJECT_FUNC fill_func;
} PERL_OBJECT_REC;

static GHashTable *iobject_stashes, *plain_stashes;
static GSList *use_protocols;

/* returns the package who called us */
const char *perl_get_package(void)
{
	return SvPV_nolen(perl_eval_pv("caller", TRUE));
}

/* Parses the package part from function name */
char *perl_function_get_package(const char *function)
{
	const char *p;
        int pos;

        pos = 0;
	for (p = function; *p != '\0'; p++) {
		if (*p == ':' && p[1] == ':') {
			if (++pos == 3)
                                return g_strndup(function, (int) (p-function));
		}
	}

        return NULL;
}

SV *perl_func_sv_inc(SV *func, const char *package)
{
	char *name;

	if (SvPOK(func)) {
		/* prefix with package name */
		name = g_strdup_printf("%s::%s", package,
				       SvPV_nolen(func));
		func = new_pv(name);
                g_free(name);
	} else {
		SvREFCNT_inc(func);
	}

        return func;
}

static int magic_free_object(pTHX_ SV *sv, MAGIC *mg)
{
	sv_setiv(sv, 0);
	return 0;
}

static MGVTBL vtbl_free_object =
{
    NULL, NULL, NULL, NULL, magic_free_object
};

static SV *create_sv_ptr(void *object)
{
	SV *sv;

	sv = newSViv((IV)object);

	sv_magic(sv, NULL, '~', NULL, 0);

	SvMAGIC(sv)->mg_private = 0x1551; /* HF */
	SvMAGIC(sv)->mg_virtual = &vtbl_free_object;

	return sv;
}

SV *irssi_bless_iobject(int type, int chat_type, void *object)
{
        PERL_OBJECT_REC *rec;
	HV *stash, *hv;

	g_return_val_if_fail((type & ~0xffff) == 0, NULL);
	g_return_val_if_fail((chat_type & ~0xffff) == 0, NULL);

	rec = g_hash_table_lookup(iobject_stashes,
				  GINT_TO_POINTER(type | (chat_type << 16)));
	if (rec == NULL) {
                /* unknown iobject */
		return create_sv_ptr(object);
	}

	stash = gv_stashpv(rec->stash, 1);

	hv = newHV();
	(void) hv_store(hv, "_irssi", 6, create_sv_ptr(object), 0);
        rec->fill_func(hv, object);
	return sv_bless(newRV_noinc((SV*)hv), stash);
}

SV *irssi_bless_plain(const char *stash, void *object)
{
        PERL_OBJECT_FUNC fill_func;
	HV *hv;

	fill_func = g_hash_table_lookup(plain_stashes, stash);

	hv = newHV();
	(void) hv_store(hv, "_irssi", 6, create_sv_ptr(object), 0);
	if (fill_func != NULL)
		fill_func(hv, object);
	return sv_bless(newRV_noinc((SV*)hv), gv_stashpv((char *)stash, 1));
}

int irssi_is_ref_object(SV *o)
{
        SV **sv;
	HV *hv;

        hv = hvref(o);
	if (hv != NULL) {
		sv = hv_fetch(hv, "_irssi", 6, 0);
		if (sv != NULL)
			return TRUE;
	}

	return FALSE;
}

void *irssi_ref_object(SV *o)
{
        SV **sv;
	HV *hv;
	void *p;

        hv = hvref(o);
	if (hv == NULL)
		return NULL;

	sv = hv_fetch(hv, "_irssi", 6, 0);
	if (sv == NULL)
		croak("variable is damaged");
	p = GINT_TO_POINTER(SvIV(*sv));
	return p;
}

void irssi_add_object(int type, int chat_type, const char *stash,
		      PERL_OBJECT_FUNC func)
{
	PERL_OBJECT_REC *rec;
        void *hash;

	g_return_if_fail((type & ~0xffff) == 0);
	g_return_if_fail((chat_type & ~0xffff) == 0);

        hash = GINT_TO_POINTER(type | (chat_type << 16));
	rec = g_hash_table_lookup(iobject_stashes, hash);
	if (rec == NULL) {
		rec = g_new(PERL_OBJECT_REC, 1);
		rec->stash = g_strdup(stash);
		g_hash_table_insert(iobject_stashes, hash, rec);
	}
	rec->fill_func = func;
}

void irssi_add_plain(const char *stash, PERL_OBJECT_FUNC func)
{
        if (g_hash_table_lookup(plain_stashes, stash) == NULL)
		g_hash_table_insert(plain_stashes, g_strdup(stash), func);
}

void irssi_add_plains(PLAIN_OBJECT_INIT_REC *objects)
{
	while (objects->name != NULL) {
                irssi_add_plain(objects->name, objects->fill_func);
                objects++;
	}
}

char *perl_get_use_list(void)
{
	GString *str;
	GSList *tmp;
        char *ret;
        const char *use_lib;

	str = g_string_new(NULL);

	use_lib = settings_get_str("perl_use_lib");
	g_string_printf(str, "use lib qw(%s/scripts "SCRIPTDIR" %s);",
			 get_irssi_dir(), use_lib);

        g_string_append(str, "use Irssi;");
	if (irssi_gui != IRSSI_GUI_NONE)
		g_string_append(str, "use Irssi::UI;");

	for (tmp = use_protocols; tmp != NULL; tmp = tmp->next)
		g_string_append_printf(str, "use Irssi::%s;", (char *) tmp->data);

	ret = g_string_free_and_steal(str);
	return ret;
}

void irssi_callXS(void (*subaddr)(pTHX_ CV* cv), CV *cv, SV **mark)
{
	PUSHMARK(mark);

	(*subaddr)(aTHX_ cv);
}

void perl_chatnet_fill_hash(HV *hv, CHATNET_REC *chatnet)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(chatnet != NULL);

	type = "CHATNET";
	chat_type = (char *) chat_protocol_find_id(chatnet->chat_type)->name;

	(void) hv_store(hv, "type", 4, new_pv(type), 0);
	(void) hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);

	(void) hv_store(hv, "name", 4, new_pv(chatnet->name), 0);

	(void) hv_store(hv, "nick", 4, new_pv(chatnet->nick), 0);
	(void) hv_store(hv, "username", 8, new_pv(chatnet->username), 0);
	(void) hv_store(hv, "realname", 8, new_pv(chatnet->realname), 0);

	(void) hv_store(hv, "own_host", 8, new_pv(chatnet->own_host), 0);
	(void) hv_store(hv, "autosendcmd", 11, new_pv(chatnet->autosendcmd), 0);
}

void perl_connect_fill_hash(HV *hv, SERVER_CONNECT_REC *conn)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(conn != NULL);

	type = "SERVER CONNECT";
	chat_type = (char *) chat_protocol_find_id(conn->chat_type)->name;

	(void) hv_store(hv, "type", 4, new_pv(type), 0);
	(void) hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);

	(void) hv_store(hv, "chosen_family", 13, newSViv(conn->chosen_family), 0);
	(void) hv_store(hv, "ipaddr", 6, new_pv(conn->ipaddr), 0);
	(void) hv_store(hv, "tag", 3, new_pv(conn->tag), 0);
	(void) hv_store(hv, "address", 7, new_pv(conn->address), 0);
	(void) hv_store(hv, "port", 4, newSViv(conn->port), 0);
	(void) hv_store(hv, "chatnet", 7, new_pv(conn->chatnet), 0);

	(void) hv_store(hv, "password", 8, new_pv(conn->password), 0);
	(void) hv_store(hv, "wanted_nick", 11, new_pv(conn->nick), 0);
	(void) hv_store(hv, "username", 8, new_pv(conn->username), 0);
	(void) hv_store(hv, "realname", 8, new_pv(conn->realname), 0);

	(void) hv_store(hv, "reconnection", 12, newSViv(conn->reconnection), 0);
	(void) hv_store(hv, "no_autojoin_channels", 20, newSViv(conn->no_autojoin_channels), 0);
	(void) hv_store(hv, "no_autosendcmd", 14, newSViv(conn->no_autosendcmd), 0);
	(void) hv_store(hv, "unix_socket", 11, newSViv(conn->unix_socket), 0);
	(void) hv_store(hv, "use_ssl", 7, newSViv(conn->use_tls), 0);
	(void) hv_store(hv, "use_tls", 7, newSViv(conn->use_tls), 0);
	(void) hv_store(hv, "no_connect", 10, newSViv(conn->no_connect), 0);
}

void perl_server_fill_hash(HV *hv, SERVER_REC *server)
{
	char *type;
	HV *stash;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(server != NULL);

	perl_connect_fill_hash(hv, server->connrec);

	type = "SERVER";
	(void) hv_store(hv, "type", 4, new_pv(type), 0);

	(void) hv_store(hv, "connect_time", 12, newSViv(server->connect_time), 0);
	(void) hv_store(hv, "real_connect_time", 17, newSViv(server->real_connect_time), 0);

	(void) hv_store(hv, "tag", 3, new_pv(server->tag), 0);
	(void) hv_store(hv, "nick", 4, new_pv(server->nick), 0);

	(void) hv_store(hv, "connected", 9, newSViv(server->connected), 0);
	(void) hv_store(hv, "connection_lost", 15, newSViv(server->connection_lost), 0);

	stash = gv_stashpv("Irssi::Rawlog", 0);
	(void) hv_store(hv, "rawlog", 6, sv_bless(newRV_noinc(newSViv((IV)server->rawlog)), stash), 0);

	(void) hv_store(hv, "version", 7, new_pv(server->version), 0);
	(void) hv_store(hv, "away_reason", 11, new_pv(server->away_reason), 0);
	(void) hv_store(hv, "last_invite", 11, new_pv(server->last_invite), 0);
	(void) hv_store(hv, "server_operator", 15, newSViv(server->server_operator), 0);
	(void) hv_store(hv, "usermode_away", 13, newSViv(server->usermode_away), 0);
	(void) hv_store(hv, "banned", 6, newSViv(server->banned), 0);

	(void) hv_store(hv, "lag", 3, newSViv(server->lag), 0);
}

void perl_window_item_fill_hash(HV *hv, WI_ITEM_REC *item)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(item != NULL);

	type = (char *) module_find_id_str("WINDOW ITEM TYPE", item->type);

	(void) hv_store(hv, "type", 4, new_pv(type), 0);
	if (item->chat_type) {
		chat_type = (char *) chat_protocol_find_id(item->chat_type)->name;
		(void) hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);
	}

	if (item->server != NULL) {
		(void) hv_store(hv, "server", 6, iobject_bless(item->server), 0);
	}
	(void) hv_store(hv, "visible_name", 12, new_pv(item->visible_name), 0);

	(void) hv_store(hv, "createtime", 10, newSViv(item->createtime), 0);
	(void) hv_store(hv, "data_level", 10, newSViv(item->data_level), 0);
	(void) hv_store(hv, "hilight_color", 13, new_pv(item->hilight_color), 0);
}

void perl_channel_fill_hash(HV *hv, CHANNEL_REC *channel)
{
        g_return_if_fail(hv != NULL);
        g_return_if_fail(channel != NULL);

	perl_window_item_fill_hash(hv, (WI_ITEM_REC *) channel);

        if (channel->ownnick != NULL)
		(void) hv_store(hv, "ownnick", 7, iobject_bless(channel->ownnick), 0);

	(void) hv_store(hv, "name", 4, new_pv(channel->name), 0);
	(void) hv_store(hv, "topic", 5, new_pv(channel->topic), 0);
	(void) hv_store(hv, "topic_by", 8, new_pv(channel->topic_by), 0);
	(void) hv_store(hv, "topic_time", 10, newSViv(channel->topic_time), 0);

	(void) hv_store(hv, "no_modes", 8, newSViv(channel->no_modes), 0);
	(void) hv_store(hv, "mode", 4, new_pv(channel->mode), 0);
	(void) hv_store(hv, "limit", 5, newSViv(channel->limit), 0);
	(void) hv_store(hv, "key", 3, new_pv(channel->key), 0);

	(void) hv_store(hv, "chanop", 6, newSViv(channel->chanop), 0);
	(void) hv_store(hv, "names_got", 9, newSViv(channel->names_got), 0);
	(void) hv_store(hv, "wholist", 7, newSViv(channel->wholist), 0);
	(void) hv_store(hv, "synced", 6, newSViv(channel->synced), 0);

	(void) hv_store(hv, "joined", 6, newSViv(channel->joined), 0);
	(void) hv_store(hv, "left", 4, newSViv(channel->left), 0);
	(void) hv_store(hv, "kicked", 6, newSViv(channel->kicked), 0);
}

void perl_query_fill_hash(HV *hv, QUERY_REC *query)
{
        g_return_if_fail(hv != NULL);
        g_return_if_fail(query != NULL);

	perl_window_item_fill_hash(hv, (WI_ITEM_REC *) query);

	(void) hv_store(hv, "name", 4, new_pv(query->name), 0);
	(void) hv_store(hv, "last_unread_msg", 15, newSViv(query->last_unread_msg), 0);
	(void) hv_store(hv, "address", 7, new_pv(query->address), 0);
	(void) hv_store(hv, "server_tag", 10, new_pv(query->server_tag), 0);
	(void) hv_store(hv, "unwanted", 8, newSViv(query->unwanted), 0);
}

void perl_nick_fill_hash(HV *hv, NICK_REC *nick)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(nick != NULL);

	type = "NICK";
	chat_type = (char *) chat_protocol_find_id(nick->chat_type)->name;

	(void) hv_store(hv, "type", 4, new_pv(type), 0);
	(void) hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);

	(void) hv_store(hv, "nick", 4, new_pv(nick->nick), 0);
	(void) hv_store(hv, "host", 4, new_pv(nick->host), 0);
	(void) hv_store(hv, "realname", 8, new_pv(nick->realname), 0);
	(void) hv_store(hv, "account", 7, new_pv(nick->account), 0);
	(void) hv_store(hv, "hops", 4, newSViv(nick->hops), 0);

	(void) hv_store(hv, "gone", 4, newSViv(nick->gone), 0);
	(void) hv_store(hv, "serverop", 8, newSViv(nick->serverop), 0);

	(void) hv_store(hv, "op", 2, newSViv(nick->op), 0);
	(void) hv_store(hv, "halfop", 6, newSViv(nick->halfop), 0);
	(void) hv_store(hv, "voice", 5, newSViv(nick->voice), 0);
	(void) hv_store(hv, "other", 5, newSViv(nick->prefixes[0]), 0);
	(void) hv_store(hv, "prefixes", 8, new_pv(nick->prefixes), 0);

	(void) hv_store(hv, "last_check", 10, newSViv(nick->last_check), 0);
	(void) hv_store(hv, "send_massjoin", 13, newSViv(nick->send_massjoin), 0);
}

static void perl_command_fill_hash(HV *hv, COMMAND_REC *cmd)
{
	(void) hv_store(hv, "category", 8, new_pv(cmd->category), 0);
	(void) hv_store(hv, "cmd", 3, new_pv(cmd->cmd), 0);
}

static void perl_ignore_fill_hash(HV *hv, IGNORE_REC *ignore)
{
	AV *av;
	char **tmp;

	(void) hv_store(hv, "mask", 4, new_pv(ignore->mask), 0);
	(void) hv_store(hv, "servertag", 9, new_pv(ignore->servertag), 0);
	av = newAV();
	if (ignore->channels != NULL) {
		for (tmp = ignore->channels; *tmp != NULL; tmp++) {
			av_push(av, new_pv(*tmp));
		}
	}
	(void) hv_store(hv, "channels", 8, newRV_noinc((SV*)av), 0);
	(void) hv_store(hv, "pattern", 7, new_pv(ignore->pattern), 0);

	(void) hv_store(hv, "level", 5, newSViv(ignore->level), 0);

	(void) hv_store(hv, "exception", 9, newSViv(ignore->exception), 0);
	(void) hv_store(hv, "regexp", 6, newSViv(ignore->regexp), 0);
	(void) hv_store(hv, "fullword", 8, newSViv(ignore->fullword), 0);
}

static void perl_log_fill_hash(HV *hv, LOG_REC *log)
{
	AV *av;
	GSList *tmp;

	(void) hv_store(hv, "fname", 5, new_pv(log->fname), 0);
	(void) hv_store(hv, "real_fname", 10, new_pv(log->real_fname), 0);
	(void) hv_store(hv, "opened", 6, newSViv(log->opened), 0);
	(void) hv_store(hv, "level", 5, newSViv(log->level), 0);
	(void) hv_store(hv, "last", 4, newSViv(log->last), 0);
	(void) hv_store(hv, "autoopen", 8, newSViv(log->autoopen), 0);
	(void) hv_store(hv, "failed", 6, newSViv(log->failed), 0);
	(void) hv_store(hv, "temp", 4, newSViv(log->temp), 0);

	av = newAV();
	for (tmp = log->items; tmp != NULL; tmp = tmp->next) {
		av_push(av, plain_bless(tmp->data, "Irssi::Logitem"));
	}
	(void) hv_store(hv, "items", 5, newRV_noinc((SV*)av), 0);
}

static void perl_log_item_fill_hash(HV *hv, LOG_ITEM_REC *item)
{
	(void) hv_store(hv, "type", 4, newSViv(item->type), 0);
	(void) hv_store(hv, "name", 4, new_pv(item->name), 0);
	(void) hv_store(hv, "servertag", 9, new_pv(item->servertag), 0);
}

static void perl_rawlog_fill_hash(HV *hv, RAWLOG_REC *rawlog)
{
	(void) hv_store(hv, "logging", 7, newSViv(rawlog->logging), 0);
	(void) hv_store(hv, "nlines", 6, newSViv(rawlog->lines->length), 0);
}

static void perl_reconnect_fill_hash(HV *hv, RECONNECT_REC *reconnect)
{
	char *type;

	perl_connect_fill_hash(hv, reconnect->conn);

	type = "RECONNECT";
	(void) hv_store(hv, "type", 4, new_pv(type), 0);

	(void) hv_store(hv, "tag", 3, newSViv(reconnect->tag), 0);
	(void) hv_store(hv, "next_connect", 12, newSViv(reconnect->next_connect), 0);
}

static void perl_script_fill_hash(HV *hv, PERL_SCRIPT_REC *script)
{
	(void) hv_store(hv, "name", 4, new_pv(script->name), 0);
	(void) hv_store(hv, "package", 7, new_pv(script->package), 0);
	(void) hv_store(hv, "path", 4, new_pv(script->path), 0);
	(void) hv_store(hv, "data", 4, new_pv(script->data), 0);
}

static void remove_newlines(char *str)
{
	char *writing = str;

	for (;*str;str++)
		if (*str != '\n' && *str != '\r')
			*(writing++) = *str;
	*writing = '\0';
}

void perl_command(const char *cmd, SERVER_REC *server, WI_ITEM_REC *item)
{
        const char *cmdchars;
	char *sendcmd = (char *) cmd;

	if (*cmd == '\0')
                return;

        cmdchars = settings_get_str("cmdchars");
	if (strchr(cmdchars, *cmd) == NULL) {
		/* no command char - let's put it there.. */
		sendcmd = g_strdup_printf("%c%s", *cmdchars, cmd);
	}

	/* remove \r and \n from commands,
	   to make it harder to introduce a security bug in a script */
	if(strpbrk(sendcmd, "\r\n")) {
		if (sendcmd == cmd)
			sendcmd = strdup(cmd);
		remove_newlines(sendcmd);
	}

	signal_emit("send command", 3, sendcmd, server, item);
	if (sendcmd != cmd) g_free(sendcmd);
}

static void perl_register_protocol(CHAT_PROTOCOL_REC *rec)
{
	static char *items[] = {
		"Chatnet",
		"Server", "ServerConnect", "ServerSetup",
		"Channel", "Query",
		"Nick"
	};
	static char *find_use_code =
		"use lib qw(%s);\n"
		"my $pkg = Irssi::%s; $pkg =~ s/::/\\//;\n"
		"foreach my $i (@INC) {\n"
		"  return 1 if (-f \"$i/$pkg.pm\");\n"
		"}\n"
		"return 0;\n";

	char *name, stash[100], code[100], *pcode;
	int type, chat_type, n;
        SV *sv;

	chat_type = chat_protocol_lookup(rec->name);
	if (chat_type == CHAT_PROTOCOL_NOT_INITIALIZED) {
		return;
	}

	g_return_if_fail(chat_type >= 0);

	name = g_ascii_strdown(rec->name,-1);
	*name = *(rec->name);

	/* window items: channel, query */
	type = module_get_uniq_id_str("WINDOW ITEM TYPE", "CHANNEL");
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Channel", name);
	irssi_add_object(type, chat_type, stash,
			 (PERL_OBJECT_FUNC) perl_channel_fill_hash);

	type = module_get_uniq_id_str("WINDOW ITEM TYPE", "QUERY");
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Query", name);
	irssi_add_object(type, chat_type, stash,
			 (PERL_OBJECT_FUNC) perl_query_fill_hash);

        /* channel nicks */
	type = module_get_uniq_id("NICK", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Nick", name);
	irssi_add_object(type, chat_type, stash,
			 (PERL_OBJECT_FUNC) perl_nick_fill_hash);

        /* chatnets */
	type = module_get_uniq_id("CHATNET", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Chatnet", name);
	irssi_add_object(type, chat_type, stash,
			 (PERL_OBJECT_FUNC) perl_chatnet_fill_hash);

	/* server specific */
	type = module_get_uniq_id("SERVER", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Server", name);
	irssi_add_object(type, chat_type, stash,
			 (PERL_OBJECT_FUNC) perl_server_fill_hash);

	type = module_get_uniq_id("SERVER CONNECT", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Connect", name);
	irssi_add_object(type, chat_type, stash,
			 (PERL_OBJECT_FUNC) perl_connect_fill_hash);

	/* register ISAs */
	for (n = 0; n < sizeof(items)/sizeof(items[0]); n++) {
		g_snprintf(code, sizeof(code),
			   "@Irssi::%s::%s::ISA = qw(Irssi::%s);",
			   name, items[n], items[n]);
		perl_eval_pv(code, TRUE);
	}

	pcode = g_strdup_printf(find_use_code,
	                        settings_get_str("perl_use_lib"), name);
	sv = perl_eval_pv(pcode, TRUE);
	g_free(pcode);

	if (SvIV(sv)) {
		use_protocols =
			g_slist_append(use_protocols, g_strdup(name));
	}

	g_free(name);
}

static void free_iobject_hash(void *key, PERL_OBJECT_REC *rec)
{
        g_free(rec->stash);
	g_free(rec);
}

static int free_iobject_proto(void *key, void *value, void *chat_type)
{
	if ((GPOINTER_TO_INT(key) >> 16) == GPOINTER_TO_INT(chat_type)) {
                free_iobject_hash(key, value);
                return TRUE;
	}

	return FALSE;
}

static void perl_unregister_protocol(CHAT_PROTOCOL_REC *rec)
{
	GSList *item;
	void *data;

	item = i_slist_find_icase_string(use_protocols, rec->name);
	if (item != NULL) {
		data = item->data;
		use_protocols = g_slist_remove(use_protocols, data);
		g_free(data);
	}
	g_hash_table_foreach_remove(iobject_stashes,
				    (GHRFunc) free_iobject_proto,
				    GINT_TO_POINTER(rec->id));
}

void perl_common_start(void)
{
	static PLAIN_OBJECT_INIT_REC core_plains[] = {
		{ "Irssi::Command", (PERL_OBJECT_FUNC) perl_command_fill_hash },
		{ "Irssi::Ignore", (PERL_OBJECT_FUNC) perl_ignore_fill_hash },
		{ "Irssi::Log", (PERL_OBJECT_FUNC) perl_log_fill_hash },
		{ "Irssi::Logitem", (PERL_OBJECT_FUNC) perl_log_item_fill_hash },
		{ "Irssi::Rawlog", (PERL_OBJECT_FUNC) perl_rawlog_fill_hash },
		{ "Irssi::Reconnect", (PERL_OBJECT_FUNC) perl_reconnect_fill_hash },
		{ "Irssi::Script", (PERL_OBJECT_FUNC) perl_script_fill_hash },

		{ NULL, NULL }
	};

	iobject_stashes = g_hash_table_new((GHashFunc) g_direct_hash,
					(GCompareFunc) g_direct_equal);
	plain_stashes = g_hash_table_new((GHashFunc) g_str_hash,
					 (GCompareFunc) g_str_equal);
        irssi_add_plains(core_plains);

        use_protocols = NULL;
	g_slist_foreach(chat_protocols, (GFunc) perl_register_protocol, NULL);

	signal_add("chat protocol created", (SIGNAL_FUNC) perl_register_protocol);
	signal_add("chat protocol destroyed", (SIGNAL_FUNC) perl_unregister_protocol);
}

void perl_common_stop(void)
{
        g_hash_table_foreach(iobject_stashes, (GHFunc) free_iobject_hash, NULL);
	g_hash_table_destroy(iobject_stashes);
        iobject_stashes = NULL;

	g_hash_table_foreach(plain_stashes, (GHFunc) g_free, NULL);
	g_hash_table_destroy(plain_stashes);
        plain_stashes = NULL;

	g_slist_foreach(use_protocols, (GFunc) g_free, NULL);
	g_slist_free(use_protocols);
        use_protocols = NULL;

	signal_remove("chat protocol created", (SIGNAL_FUNC) perl_register_protocol);
	signal_remove("chat protocol destroyed", (SIGNAL_FUNC) perl_unregister_protocol);
}
