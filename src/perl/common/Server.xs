#include "module.h"

MODULE = Irssi::Server  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
servers()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(irssi_bless((SERVER_REC *) tmp->data)));
	}

void
reconnects()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Reconnect")));
	}

Irssi::Connect
server_create_conn(chat_type, dest, port=6667, chatnet=NULL, password=NULL, nick=NULL)
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

#*******************************
MODULE = Irssi::Server	PACKAGE = Irssi::Server  PREFIX = server_
#*******************************

void
server_disconnect(server)
	Irssi::Server server

int
isnickflag(server, flag)
	Irssi::Server server
	char flag
CODE:
	RETVAL = server->isnickflag(flag);
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
	RETVAL = (char *) server->get_nick_flags();
OUTPUT:
	RETVAL

void
send_message(server, target, msg)
	Irssi::Server server
	char *target
	char *msg
CODE:
	server->send_message(server, target, msg);

