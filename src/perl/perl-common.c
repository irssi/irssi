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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <EXTERN.h>
#ifndef _SEM_SEMUN_UNDEFINED
#define HAS_UNION_SEMUN
#endif
#include <perl.h>

#undef _
#undef PACKAGE

#include "module.h"
#include "modules.h"
#include "signals.h"
#include "settings.h"

#include "chat-protocols.h"
#include "servers.h"
#include "channels.h"
#include "queries.h"
#include "nicklist.h"

#include "perl-common.h"

#include "fe-common/core/formats.h"
#include "fe-common/core/printtext.h"

static GHashTable *perl_stashes;

/* returns the package who called us */
char *perl_get_package(void)
{
	STRLEN n_a;
	return SvPV(perl_eval_pv("caller", TRUE), n_a);
}

static void object_fill_values(SV *sv, const char *stash)
{
	dSP;
        char str[100];

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_mortalcopy(sv));
	PUTBACK;

	g_snprintf(str, sizeof(str), "%s::init", stash);
	perl_call_method(str, G_DISCARD);
	SPAGAIN;

	PUTBACK;
	FREETMPS;
	LEAVE;
}

SV *irssi_bless_object(int type, int chat_type, void *object)
{
        char *str;
	HV *stash, *hv;
        SV *sv;

	str = g_hash_table_lookup(perl_stashes,
				  GINT_TO_POINTER(type | (chat_type << 24)));
	g_return_val_if_fail(str != NULL, newSViv(GPOINTER_TO_INT(object)));

	stash = gv_stashpv(str, 1);

	hv = newHV();
	hv_store(hv, "_irssi", 6, newSViv(GPOINTER_TO_INT(object)), 0);

	sv = sv_bless(newRV_noinc((SV*)hv), stash);
	object_fill_values(sv, str);
        return sv;

}

void *irssi_ref_object(SV *o)
{
        SV **sv;
	HV *hv;

        hv = hvref(o);
	if (hv == NULL)
		return 0;

	sv = hv_fetch(hv, "_irssi", 6, 0);
	if (sv == NULL)
                croak("variable is damaged");
	return GINT_TO_POINTER(SvIV(*sv));
}

void irssi_add_object(int type, int chat_type, const char *stash)
{
	g_hash_table_insert(perl_stashes,
			    GINT_TO_POINTER(type | (chat_type << 24)),
			    g_strdup(stash));
}

void perl_connect_fill_hash(HV *hv, SERVER_CONNECT_REC *conn)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(conn != NULL);

	type = "SERVER CONNECT";
	chat_type = (char *) chat_protocol_find_id(conn->chat_type)->name;

	hv_store(hv, "type", 4, new_pv(type), 0);
	hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);

	hv_store(hv, "address", 7, new_pv(conn->address), 0);
	hv_store(hv, "port", 4, newSViv(conn->port), 0);
	hv_store(hv, "chatnet", 7, new_pv(conn->chatnet), 0);

	hv_store(hv, "password", 8, new_pv(conn->password), 0);
	hv_store(hv, "wanted_nick", 11, new_pv(conn->nick), 0);
	hv_store(hv, "username", 8, new_pv(conn->username), 0);
	hv_store(hv, "realname", 8, new_pv(conn->realname), 0);
}

void perl_server_fill_hash(HV *hv, SERVER_REC *server)
{
	char *type, *chat_type;
	HV *stash;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(server != NULL);

	perl_connect_fill_hash(hv, server->connrec);

	type = "SERVER";
	chat_type = (char *) chat_protocol_find_id(server->chat_type)->name;

	hv_store(hv, "type", 4, new_pv(type), 0);
	hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);

	hv_store(hv, "connect_time", 12, newSViv(server->connect_time), 0);
	hv_store(hv, "real_connect_time", 17, newSViv(server->real_connect_time), 0);

	hv_store(hv, "tag", 3, new_pv(server->tag), 0);
	hv_store(hv, "nick", 4, new_pv(server->nick), 0);

	hv_store(hv, "connected", 9, newSViv(server->connected), 0);
	hv_store(hv, "connection_lost", 15, newSViv(server->connection_lost), 0);

	stash = gv_stashpv("Irssi::Rawlog", 0);
	hv_store(hv, "rawlog", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(server->rawlog))), stash), 0);

	hv_store(hv, "version", 7, new_pv(server->version), 0);
	hv_store(hv, "away_reason", 11, new_pv(server->away_reason), 0);
	hv_store(hv, "last_invite", 11, new_pv(server->last_invite), 0);
	hv_store(hv, "server_operator", 15, newSViv(server->server_operator), 0);
	hv_store(hv, "usermode_away", 13, newSViv(server->usermode_away), 0);
	hv_store(hv, "banned", 6, newSViv(server->banned), 0);

	hv_store(hv, "lag", 3, newSViv(server->lag), 0);
}

void perl_window_item_fill_hash(HV *hv, WI_ITEM_REC *item)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(item != NULL);

	type = (char *) module_find_id_str("WINDOW ITEM", item->type);
	chat_type = (char *) chat_protocol_find_id(item->chat_type)->name;

	hv_store(hv, "type", 4, new_pv(type), 0);
	hv_store(hv, "chat_type", 9, new_pv(chat_type), 0);

	if (item->server != NULL) {
		hv_store(hv, "server", 6, irssi_bless(item->server), 0);
	}
	hv_store(hv, "name", 4, new_pv(item->name), 0);

	hv_store(hv, "createtime", 10, newSViv(item->createtime), 0);
	hv_store(hv, "new_data", 8, newSViv(item->new_data), 0);
	hv_store(hv, "last_color", 10, newSViv(item->last_color), 0);
}

void perl_channel_fill_hash(HV *hv, CHANNEL_REC *channel)
{
        g_return_if_fail(hv != NULL);
        g_return_if_fail(channel != NULL);

	perl_window_item_fill_hash(hv, (WI_ITEM_REC *) channel);

	hv_store(hv, "topic", 5, new_pv(channel->topic), 0);

	hv_store(hv, "no_modes", 8, newSViv(channel->no_modes), 0);
	hv_store(hv, "mode", 4, new_pv(channel->mode), 0);
	hv_store(hv, "limit", 5, newSViv(channel->limit), 0);
	hv_store(hv, "key", 3, new_pv(channel->key), 0);

	hv_store(hv, "chanop", 6, newSViv(channel->chanop), 0);
	hv_store(hv, "names_got", 9, newSViv(channel->names_got), 0);
	hv_store(hv, "wholist", 7, newSViv(channel->wholist), 0);
	hv_store(hv, "synced", 6, newSViv(channel->synced), 0);

	hv_store(hv, "joined", 6, newSViv(channel->joined), 0);
	hv_store(hv, "left", 4, newSViv(channel->left), 0);
	hv_store(hv, "kicked", 6, newSViv(channel->kicked), 0);
}

void perl_query_fill_hash(HV *hv, QUERY_REC *query)
{
        g_return_if_fail(hv != NULL);
        g_return_if_fail(query != NULL);

	perl_window_item_fill_hash(hv, (WI_ITEM_REC *) query);

	hv_store(hv, "address", 7, new_pv(query->address), 0);
	hv_store(hv, "server_tag", 10, new_pv(query->server_tag), 0);
	hv_store(hv, "unwanted", 8, newSViv(query->unwanted), 0);
}

void perl_nick_fill_hash(HV *hv, NICK_REC *nick)
{
	char *type, *chat_type;

        g_return_if_fail(hv != NULL);
        g_return_if_fail(nick != NULL);

	type = "NICK";
	chat_type = (char *) chat_protocol_find_id(nick->chat_type)->name;

	hv_store(hv, "last_check", 10, newSViv(nick->last_check), 0);

	hv_store(hv, "nick", 4, new_pv(nick->nick), 0);
	hv_store(hv, "host", 4, new_pv(nick->host), 0);
	hv_store(hv, "realname", 8, new_pv(nick->realname), 0);
	hv_store(hv, "hops", 4, newSViv(nick->hops), 0);

	hv_store(hv, "gone", 4, newSViv(nick->gone), 0);
	hv_store(hv, "serverop", 8, newSViv(nick->serverop), 0);

	hv_store(hv, "send_massjoin", 13, newSViv(nick->send_massjoin), 0);
	hv_store(hv, "op", 2, newSViv(nick->op), 0);
	hv_store(hv, "halfop", 6, newSViv(nick->halfop), 0);
	hv_store(hv, "voice", 5, newSViv(nick->voice), 0);
}

void printformat_perl(TEXT_DEST_REC *dest, char *format, char **arglist)
{
	THEME_REC *theme;
	char *module, *str;
	int formatnum;

	module = g_strdup(perl_get_package());
	theme = dest->window->theme == NULL ? current_theme :
		dest->window->theme;

	formatnum = format_find_tag(module, format);
	signal_emit("print format", 5, theme, module,
		    &dest, GINT_TO_POINTER(formatnum), arglist);

        str = format_get_text_theme_charargs(theme, module, dest, formatnum, arglist);
	if (*str != '\0') printtext_window(dest->window, dest->level, "%s", str);
	g_free(str);
	g_free(module);
}

void perl_command(const char *cmd, SERVER_REC *server, WI_ITEM_REC *item)
{
        const char *cmdchars;
	char *sendcmd = (char *) cmd;

        cmdchars = settings_get_str("cmdchars");
	if (strchr(cmdchars, *cmd) == NULL) {
		/* no command char - let's put it there.. */
		sendcmd = g_strdup_printf("%c%s", *cmdchars, cmd);
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
	char *name, stash[100], code[100];
	int type, chat_type, n;

	chat_type = chat_protocol_lookup(rec->name);
	g_return_if_fail(chat_type >= 0);

	name = g_strdup(rec->name);
	g_strdown(name+1);

	/* window items: channel, query */
	type = module_get_uniq_id_str("WINDOW ITEM TYPE", "CHANNEL");
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Channel", name);
	irssi_add_object(type, chat_type, stash);

	type = module_get_uniq_id_str("WINDOW ITEM TYPE", "QUERY");
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Query", name);
	irssi_add_object(type, chat_type, stash);

        /* channel nicks */
	type = module_get_uniq_id("NICK", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Nick", name);
	irssi_add_object(type, chat_type, stash);

	/* server specific */
	type = module_get_uniq_id("SERVER", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Server", name);
	irssi_add_object(type, chat_type, stash);

	type = module_get_uniq_id("SERVER CONNECT", 0);
	g_snprintf(stash, sizeof(stash), "Irssi::%s::Connect", name);
	irssi_add_object(type, chat_type, stash);

	/* register ISAs */
	for (n = 0; n < sizeof(items)/sizeof(items[0]); n++) {
		g_snprintf(code, sizeof(code),
			   "@Irssi::%s::%s::ISA = qw(Irssi::%s);",
			   name, items[n], items[n]);
		perl_eval_pv(code, TRUE);
	}
	g_free(name);
}

static int perl_free_protocol(void *key, void *value, void *chat_type)
{
	if ((GPOINTER_TO_INT(key) >> 24) == GPOINTER_TO_INT(chat_type)) {
		g_free(value);
                return TRUE;
	}

	return FALSE;
}

static void perl_unregister_protocol(CHAT_PROTOCOL_REC *rec)
{
	g_hash_table_foreach_remove(perl_stashes, (GHRFunc) perl_free_protocol,
				    GINT_TO_POINTER(rec->id));
}

static void free_perl_stash(void *key, char *value)
{
	g_free(value);
}

static void sig_protocol_created(CHAT_PROTOCOL_REC *rec)
{
        perl_register_protocol(rec);
}

static void sig_protocol_destroyed(CHAT_PROTOCOL_REC *rec)
{
        perl_unregister_protocol(rec);
}

void perl_common_init(void)
{
	perl_stashes = g_hash_table_new((GHashFunc) g_direct_hash,
					(GCompareFunc) g_direct_equal);
	g_slist_foreach(chat_protocols, (GFunc) perl_register_protocol, NULL);

	signal_add("chat protocol created", (SIGNAL_FUNC) sig_protocol_created);
	signal_add("chat protocol destroyed", (SIGNAL_FUNC) sig_protocol_destroyed);
}

void perl_common_deinit(void)
{
        g_hash_table_foreach(perl_stashes, (GHFunc) free_perl_stash, NULL);
	g_hash_table_destroy(perl_stashes);

	signal_remove("chat protocol created", (SIGNAL_FUNC) sig_protocol_created);
	signal_remove("chat protocol destroyed", (SIGNAL_FUNC) sig_protocol_destroyed);
}
