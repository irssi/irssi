#include "module.h"

MODULE = Irssi::Server  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
servers()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(iobject_bless((SERVER_REC *) tmp->data)));
	}

void
reconnects()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Reconnect")));
	}

void
chatnets()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = chatnets; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(iobject_bless((CHATNET_REC *) tmp->data)));
	}

Irssi::Connect
server_create_conn(chat_type, dest, port, chatnet=NULL, password=NULL, nick=NULL)
	int chat_type
	char *dest
	int port
	char *chatnet
	char *password
	char *nick

Irssi::Server
server_find_tag(tag)
	char *tag

Irssi::Server
server_find_chatnet(chatnet)
	char *chatnet

Irssi::Chatnet
chatnet_find(name)
	char *name

#*******************************
MODULE = Irssi::Server	PACKAGE = Irssi::Server  PREFIX = server_
#*******************************

void
server_disconnect(server)
	Irssi::Server server

void
server_ref(server)
	Irssi::Server server

void
server_unref(server)
	Irssi::Server server

int
isnickflag(server, flag)
	Irssi::Server server
	char flag
CODE:
	RETVAL = server->isnickflag(server, flag);
OUTPUT:
	RETVAL

int
ischannel(server, data)
	Irssi::Server server
	char *data
CODE:
	RETVAL = server->ischannel(server, data);
OUTPUT:
	RETVAL

char *
get_nick_flags(server)
	Irssi::Server server
CODE:
	RETVAL = (char *) server->get_nick_flags(server);
OUTPUT:
	RETVAL

void
send_message(server, target, msg, target_type)
	Irssi::Server server
	char *target
	char *msg
	int target_type
CODE:
	server->send_message(server, target, msg, target_type);

