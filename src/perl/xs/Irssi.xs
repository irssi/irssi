/* This could be split to different files / modules ..? */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#undef _
#include <irssi-plugin.h>
#include <irc-base/server-setup.h>
#include <irc-base/server-reconnect.h>
#include <irc-base/server-redirect.h>

typedef SERVER_REC *Irssi__Server;
typedef SERVER_CONNECT_REC *Irssi__Connect;
typedef RECONNECT_REC *Irssi__Reconnect;
typedef CHANNEL_REC *Irssi__Channel;
typedef COMMAND_REC *Irssi__Command;
typedef NICK_REC *Irssi__Nick;
typedef BAN_REC *Irssi__Ban;
typedef DCC_REC *Irssi__Dcc;
typedef NETSPLIT_REC *Irssi__Netsplit;
typedef AUTOIGNORE_REC *Irssi__Autoignore;
typedef LOG_REC *Irssi__Log;
typedef LOG_ITEM_REC *Irssi__Logitem;
typedef PLUGIN_REC *Irssi__Plugin;

#define new_pv(a) (newSVpv((a) == NULL ? "" : (a), (a) == NULL ? 0 : strlen(a)))

void add_connect_hash(HV *hv, SERVER_CONNECT_REC *conn)
{
	hv_store(hv, "address", 7, new_pv(conn->address), 0);
	hv_store(hv, "port", 4, newSViv(conn->port), 0);
	hv_store(hv, "password", 8, new_pv(conn->password), 0);

	hv_store(hv, "ircnet", 6, new_pv(conn->ircnet), 0);
	hv_store(hv, "wanted_nick", 11, new_pv(conn->nick), 0);
	hv_store(hv, "alternate_nick", 14, new_pv(conn->alternate_nick), 0);
	hv_store(hv, "username", 8, new_pv(conn->username), 0);
	hv_store(hv, "realname", 8, new_pv(conn->realname), 0);
	hv_store(hv, "autojoin_channels", 17, new_pv(conn->autojoin_channels), 0);
}

MODULE = Irssi	PACKAGE = Irssi

PROTOTYPES: ENABLE

Irssi::Channel
cur_channel()
CODE:
	RETVAL = cur_channel;
OUTPUT:
	RETVAL

Irssi::Server
cur_server()
CODE:
	RETVAL = cur_channel->server;
OUTPUT:
	RETVAL

void
channels()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Channel", 0);
	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

void
servers()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Server", 0);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

void
commands()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Command", 0);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

void
dccs()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Dcc", 0);
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

void
logs()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Log", 0);
	for (tmp = logs; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

void
plugins()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Plugin", 0);
	for (tmp = plugins; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

Irssi::Connect
server_create_conn(dest, port=6667, password=NULL, nick=NULL, channels=NULL)
	char *dest
	int port
	char *password
	char *nick
	char *channels

Irssi::Server
server_find_tag(tag)
	char *tag

Irssi::Server
server_find_ircnet(ircnet)
	char *ircnet

Irssi::Channel
channel_find(channel)
	char *channel
CODE:
	RETVAL = channel_find(NULL, channel);
OUTPUT:
	RETVAL

void
print(str)
	char *str
CODE:
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, str);

void
signal_emit(signal, ...)
	char *signal
CODE:
	void *p[6];
	int n;

	memset(p, 0, sizeof(p));
	for (n = 1; n < items && n < 6; n++) {
		p[n-1] = SvPOKp(ST(n)) ? SvPV(ST(n), PL_na) : (void *) SvIV((SV*)SvRV(ST(n)));
	}
	signal_emit(signal, items-1, p[0], p[1], p[2], p[3], p[4], p[5]);

void
signal_add(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_add(signal, func);

void
signal_add_last(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_add_last(signal, func);

void
signal_remove(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_remove(signal, func);

int
timeout_add(msecs, func, data)
	int msecs
	char *func
	char *data
CODE:
	RETVAL = perl_timeout_add(msecs, func, data);
OUTPUT:
	RETVAL

void
timeout_remove(tag)
	int tag
CODE:
	perl_timeout_remove(tag);

void
command_bind(cmd, category, func)
	char *cmd
	char *category
	char *func
CODE:
	char *signal;

	command_bind(cmd, *category ? category : "Perl scripts' commands", NULL);
	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_add(signal, func);
	g_free(signal);

void
command_unbind(cmd, func)
	char *cmd
	char *func
CODE:
	char *signal;

	command_unbind(cmd, NULL);
	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_remove(signal, func);
	g_free(signal);

void
command(cmd, server=cur_channel->server, channel=cur_channel)
	char *cmd
	Irssi::Server server
	Irssi::Channel channel
CODE:
	signal_emit("send command", 3, cmd, server, channel);

int
is_channel(text)
	char *text
CODE:
	RETVAL = ischannel(*text);
OUTPUT:
	RETVAL

int
irc_mask_match(mask, nick, user, host)
	char *mask
	char *nick
	char *user
	char *host

int
irc_mask_match_address(mask, nick, address)
	char *mask
	char *nick
	char *address

int
irc_masks_match(masks, nick, address)
	char *masks
	char *nick
	char *address

char *
irc_get_mask(nick, host, flags)
	char *nick
	char *host
	int flags

int
level2bits(str)
	char *str

char *
bits2level(bits)
	int bits

int
combine_level(level, str)
	int level
	char *str

Irssi::Dcc
dcc_find_item(type, nick, arg)
	int type
	char *nick
	char *arg

Irssi::Dcc
dcc_find_by_port(nick, port)
	char *nick
	int port

char *
dcc_type2str(type)
	int type

int
dcc_str2type(type)
	char *type

void
ignore_add(mask, level)
	char *mask
	char *level

void
ignore_remove(mask, level)
	char *mask
	char *level

Irssi::Log
log_create(fname, data)
	char *fname
	char *data

Irssi::Log
log_create_with_level(fname, level)
	char *fname
	int level

Irssi::Log
log_file_find(fname)
	char *fname

void
notifylist_add(nick, ircnet)
	char *nick
	char *ircnet

Irssi::Server
notifylist_ison(nick, serverlist)
	char *nick
	char *serverlist

int
plugin_load(name, args)
	char *name
	char *args

char *
plugin_get_description(name)
	char *name

Irssi::Plugin
plugin_find(name)
	char *name

void
setup_get(option)
	char *option
PREINIT:
        char *ret;
PPCODE:
	switch(setup_option_type(option)) {
	case SETUP_TYPE_TOGGLEBUTTON:
		XPUSHs(sv_2mortal(newSViv(setup_get_bool(option))));
		break;
	case SETUP_TYPE_SPIN:
	case SETUP_TYPE_INT_OBJECT:
		XPUSHs(sv_2mortal(newSViv(setup_get_int(option))));
		break;
	case SETUP_TYPE_ENTRY:
		ret = setup_get_str(option);
		XPUSHs(sv_2mortal(newSVpv(ret, strlen(ret))));
		break;
	}


#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Server  PREFIX = server_
#*******************************************************

void
send_raw(server, cmd)
	Irssi::Server server
	char *cmd
CODE:
	irc_send_cmd(server, cmd);

void
command(server, cmd, channel=cur_channel)
	char *cmd
	Irssi::Server server
	Irssi::Channel channel
CODE:
	if (channel->server != server) {
		GSList *tmp;

		for (tmp = channels; tmp != NULL; tmp = tmp->next) {
			CHANNEL_REC *rec = tmp->data;

			if (rec->server == server) {
				channel = rec;
				break;
			}
		}
	}
	signal_emit("send command", 3, cmd, server, channel);

void
server_disconnect(server)
	Irssi::Server server

Irssi::Channel
channel_create(server, channel, type, automatic)
	Irssi::Server server
	char *channel
	int type
	int automatic

Irssi::Channel
channel_find(server, channel)
	Irssi::Server server
	char *channel

Irssi::Channel
channel_find_closest(server, channel, level)
	Irssi::Server server
	char *channel
	int level

Irssi::Channel
channel_find_level(server, level)
	Irssi::Server server
	int level

void
printtext(server, channel, level, str)
	Irssi::Server server
	char *channel
	int level
	char *str
CODE:
	printtext(server, channel, level, str);

void
irc_send_cmd_split(server, cmd, arg, max_nicks)
	Irssi::Server server
	char *cmd
	int arg
	int max_nicks

void
ctcp_send_reply(server, data)
	Irssi::Server server
	char *data

Irssi::Netsplit
netsplit_find(server, nick, address)
	Irssi::Server server
	char *nick
	char *address

Irssi::Nick
netsplit_find_channel(server, nick, address, channel)
	Irssi::Server server
	char *nick
	char *address
	char *channel

void
rawlog_input(server, str)
	Irssi::Server server
	char *str

void
rawlog_output(server, str)
	Irssi::Server server
	char *str

void
rawlog_redirect(server, str)
	Irssi::Server server
	char *str

void
server_redirect_init(server, command, last, ...)
	Irssi::Server server
	char *command
	int last
PREINIT:
	GSList *list;
	int n;
CODE:
	list = NULL;
	for (n = 3; n < items; n++) {
		list = g_slist_append(list, SvPV(ST(n), PL_na));
	}
	server_redirect_initv(server, command, last, list);

int
server_redirect_single_event(server, arg, last, group, event, signal, argpos)
	Irssi::Server server
	char *arg
	int last
	int group
	char *event
	char *signal
	int argpos

void
server_redirect_event(server, arg, last, ...)
	Irssi::Server server
	char *arg
	int last
PREINIT:
	int n, group;
CODE:
	group = 0;
	for (n = 3; n+3 <= items; n += 3, last--) {
		group = server_redirect_single_event(server, arg, last > 0, group,
			(char *) SvPV(ST(n), PL_na), (char *) SvPV(ST(n+1), PL_na), (int) SvIV(ST(n+2)));
	}

void
autoignore_add(server, type, nick)
	Irssi::Server server
	int type
	char *nick

int
autoignore_remove(server, mask, level)
	Irssi::Server server
	char *mask
	char *level

int
ignore_check(server, nick, host, type)
	Irssi::Server server
	char *nick
	char *host
	int type

int
notifylist_ison_server(server, nick)
	Irssi::Server server
	char *nick

void
values(server)
	Irssi::Server server
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	add_connect_hash(hv, server->connrec);
	hv_store(hv, "real_address", 12, new_pv(server->real_address), 0);
	hv_store(hv, "tag", 3, new_pv(server->tag), 0);
	hv_store(hv, "nick", 4, new_pv(server->nick), 0);
	hv_store(hv, "usermode", 8, new_pv(server->usermode), 0);
	hv_store(hv, "usermode_away", 13, newSViv(server->usermode_away), 0);
	hv_store(hv, "away_reason", 11, new_pv(server->away_reason), 0);
	hv_store(hv, "connected", 9, newSViv(server->connected), 0);
	hv_store(hv, "connection_lost", 15, newSViv(server->connection_lost), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Connect  PREFIX = server_
#*******************************************************

void
values(conn)
	Irssi::Connect conn
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	add_connect_hash(hv, conn);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

Irssi::Server
server_connect(conn)
	Irssi::Connect conn

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Reconnect
#*******************************************************

void
values(reconnect)
	Irssi::Reconnect reconnect
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	add_connect_hash(hv, reconnect->conn);
	hv_store(hv, "tag", 3, newSViv(reconnect->tag), 0);
	hv_store(hv, "next_connect", 12, newSViv(reconnect->next_connect), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Channel  PREFIX = channel_
#*******************************************************

void
command(channel, cmd)
	Irssi::Channel channel
	char *cmd
CODE:
	signal_emit("send command", 3, cmd, channel->server, channel);

void
channel_destroy(channel)
	Irssi::Channel channel

void
channel_change_name(channel, name)
	Irssi::Channel channel
	char *name

char *
channel_get_mode(channel)
        Irssi::Channel channel

Irssi::Nick
nicklist_insert(channel, nick, op, voice, send_massjoin)
	Irssi::Channel channel
	char *nick
	int op
	int voice
	int send_massjoin

void
nicklist_remove(channel, nick)
	Irssi::Channel channel
	Irssi::Nick nick

Irssi::Nick
nicklist_find(channel, mask)
	Irssi::Channel channel
	char *mask

void
nicklist_getnicks(channel)
	Irssi::Channel channel
PREINIT:
	GSList *list, *tmp;
	HV *stash;
PPCODE:
	list = nicklist_getnicks(channel);

	stash = gv_stashpv("Irssi::Nick", 0);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}
	g_slist_free(list);

Irssi::Ban
ban_add(channel, ban, nick, time)
	Irssi::Channel channel
	char *ban
	char *nick
	time_t time

void
ban_remove(channel, ban)
	Irssi::Channel channel
	char *ban

Irssi::Ban
ban_exception_add(channel, ban, nick, time)
	Irssi::Channel channel
	char *ban
	char *nick
	time_t time

void
ban_exception_remove(channel, ban)
	Irssi::Channel channel
	char *ban

char *
ban_get_mask(channel, nick)
	Irssi::Channel channel
	char *nick

void
modes_set(channel, data, mode)
	Irssi::Channel channel
	char *data
	char *mode
CODE:
	modes_set(data, mode, channel->server, channel);

void
modes_parse_channel(channel, setby, modestr)
	Irssi::Channel channel
	char *setby
	char *modestr

void
invitelist_add(channel, mask)
	Irssi::Channel channel
	char *mask

void
invitelist_remove(channel, mask)
	Irssi::Channel channel
	char *mask

void
values(channel)
	Irssi::Channel channel
PREINIT:
        HV *hv, *stash;
	char *type;
PPCODE:
	switch (channel->type)
	{
	case CHANNEL_TYPE_CHANNEL:
		type = "channel";
		break;
	case CHANNEL_TYPE_QUERY:
		type = "query";
		break;
	case CHANNEL_TYPE_DCC_CHAT:
		type = "dcc chat";
		break;
	default:
		type = "empty";
		break;
	}
	hv = newHV();
	stash = gv_stashpv("Irssi::Server", 0);
	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(channel->server))), stash), 0);

	hv_store(hv, "name", 4, new_pv(channel->name), 0);
	hv_store(hv, "type", 4, new_pv(type), 0);

	hv_store(hv, "topic", 5, new_pv(channel->topic), 0);
	hv_store(hv, "key", 3, new_pv(channel->key), 0);
	hv_store(hv, "limit", 5, newSViv(channel->limit), 0);

	hv_store(hv, "level", 5, newSViv(channel->level), 0);
	hv_store(hv, "new_data", 8, newSViv(channel->new_data), 0);

	hv_store(hv, "synced", 6, newSViv(channel->synced), 0);
	hv_store(hv, "wholist", 7, newSViv(channel->wholist), 0);
	hv_store(hv, "names_got", 9, newSViv(channel->names_got), 0);
	hv_store(hv, "chanop", 6, newSViv(channel->chanop), 0);
	hv_store(hv, "left", 4, newSViv(channel->left), 0);
	hv_store(hv, "kicked", 6, newSViv(channel->kicked), 0);

	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Command
#*******************************************************

void
values(cmd)
	Irssi::Command cmd
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "cmd", 3, new_pv(cmd->cmd), 0);
	hv_store(hv, "category", 8, new_pv(cmd->category), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Nick
#*******************************************************

void
values(nick)
	Irssi::Nick nick
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "nick", 4, new_pv(nick->nick), 0);
	hv_store(hv, "host", 4, new_pv(nick->host), 0);
	hv_store(hv, "name", 4, new_pv(nick->realname), 0);
	hv_store(hv, "hops", 4, newSViv(nick->hops), 0);
	hv_store(hv, "op", 2, newSViv(nick->op), 0);
	hv_store(hv, "voice", 5, newSViv(nick->voice), 0);
	hv_store(hv, "gone", 4, newSViv(nick->gone), 0);
	hv_store(hv, "ircop", 5, newSViv(nick->ircop), 0);
	hv_store(hv, "last_check", 10, newSViv(nick->last_check), 0);
	hv_store(hv, "send_massjoin", 13, newSViv(nick->send_massjoin), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Ban
#*******************************************************

void
values(ban)
	Irssi::Ban ban
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "ban", 3, new_pv(ban->ban), 0);
	hv_store(hv, "setby", 5, new_pv(ban->setby), 0);
	hv_store(hv, "time", 4, newSViv(ban->time), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Dcc  PREFIX = dcc_
#*******************************************************

void
dcc_destroy(dcc)
	Irssi::Dcc dcc

void
values(ban)
	Irssi::Ban ban
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "ban", 3, new_pv(ban->ban), 0);
	hv_store(hv, "setby", 5, new_pv(ban->setby), 0);
	hv_store(hv, "time", 4, newSViv(ban->time), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Netsplit
#*******************************************************

void
values(netsplit)
	Irssi::Netsplit netsplit
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "nick", 4, new_pv(netsplit->nick), 0);
	hv_store(hv, "address", 7, new_pv(netsplit->address), 0);
	hv_store(hv, "server", 6, new_pv(netsplit->server), 0);
	hv_store(hv, "destserver", 10, new_pv(netsplit->destserver), 0);
	hv_store(hv, "destroy", 7, newSViv(netsplit->destroy), 0);
	/*FIXME: add GSList *channels;*/
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Autoignore
#*******************************************************

void
values(ai)
	Irssi::Autoignore ai
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "nick", 4, new_pv(ai->nick), 0);
	hv_store(hv, "timeleft", 8, newSViv(ai->timeleft), 0);
	hv_store(hv, "level", 5, newSViv(ai->level), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Log  PREFIX = log_
#*******************************************************

void
values(log)
	Irssi::Log log
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "fname", 5, new_pv(log->fname), 0);
	hv_store(hv, "autoopen_log", 12, newSViv(log->autoopen_log), 0);
	hv_store(hv, "last", 4, newSViv(log->last), 0);
	hv_store(hv, "level", 5, newSViv(log->level), 0);
	/*FIXME: add GSList *items;*/
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
destroy(log)
	Irssi::Log log
CODE:
	log_file_destroy(log);

int
open(log)
	Irssi::Log log
CODE:
	log_file_open(log);

void
close(log)
	Irssi::Log log
CODE:
	log_file_close(log);

void
log_append_item(log, name, level)
	Irssi::Log log
	char *name
	int level

void
log_remove_item(log, name)
	Irssi::Log log
	char *name

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Logitem
#*******************************************************

void
values(item)
	Irssi::Logitem item
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "name", 4, new_pv(item->name), 0);
	hv_store(hv, "level", 5, newSViv(item->level), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************************************
MODULE = Irssi	PACKAGE = Irssi::Plugin  PREFIX = plugin_
#*******************************************************

void
values(plugin)
	Irssi::Plugin plugin
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "name", 4, new_pv(plugin->name), 0);
	hv_store(hv, "description", 11, new_pv(plugin->description), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
