#include "module.h"

MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Irc
PROTOTYPES: ENABLE

void
dccs()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) 
		XPUSHs(sv_2mortal(simple_iobject_bless((DCC_REC *) tmp->data)));

void
dcc_register_type(type)
	char *type

void
dcc_unregister_type(type)
	char *type

int
dcc_str2type(str)
	char *str

char *
dcc_type2str(type)
	int type
CODE:
	RETVAL = (char *) module_find_id_str("DCC", type);
OUTPUT:
	RETVAL

Irssi::Irc::Dcc
dcc_find_request_latest(type)
	int type

Irssi::Irc::Dcc
dcc_find_request(type, nick, arg)
	int type
	char *nick
	char *arg

Irssi::Irc::Dcc::Chat
dcc_chat_find_id(id)
	char *id

void
dcc_chat_send(dcc, data)
	Irssi::Irc::Dcc::Chat dcc
	char *data

void
dcc_ctcp_message(server, target, chat, notice, msg)
	Irssi::Irc::Server server
	char *target
	Irssi::Irc::Dcc::Chat chat
	int notice
	char *msg

void
dcc_get_download_path(fname)
	char *fname
PREINIT:
	char *ret;
PPCODE:
	ret = dcc_get_download_path(fname);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free(ret);

#*******************************
MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Irc::Dcc  PREFIX = dcc_
#*******************************

void
dcc_init_rec(dcc, server, chat, nick, arg)
	Irssi::Irc::Dcc dcc
	Irssi::Irc::Server server
	Irssi::Irc::Dcc::Chat chat
	char *nick
	char *arg

void
dcc_destroy(dcc)
	Irssi::Irc::Dcc dcc

void
dcc_close(dcc)
	Irssi::Irc::Dcc dcc

void
dcc_reject(dcc, server)
	Irssi::Irc::Dcc dcc
	Irssi::Irc::Server server

#*******************************
MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Windowitem  PREFIX = item_
#*******************************

Irssi::Irc::Dcc::Chat
item_get_dcc(item)
	Irssi::Windowitem item
