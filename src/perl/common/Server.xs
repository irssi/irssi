MODULE = Irssi  PACKAGE = Irssi

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
MODULE = Irssi	PACKAGE = Irssi::Server  PREFIX = server_
#*******************************

void
server_disconnect(server)
	Irssi::Server server

void
server_redirect_init(server, command, last, ...)
	Irssi::Server server
	char *command
	int last
PREINIT:
        STRLEN n_a;
	GSList *list;
	int n;
CODE:
	list = NULL;
	for (n = 3; n < items; n++) {
		list = g_slist_append(list, SvPV(ST(n), n_a));
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
        STRLEN n_a;
	int n, group;
CODE:
	group = 0;
	for (n = 3; n+3 <= items; n += 3, last--) {
		group = server_redirect_single_event(server, arg, last > 0, group,
			(char *) SvPV(ST(n), n_a), (char *) SvPV(ST(n+1), n_a), (int) SvIV(ST(n+2)));
	}

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
	RETVAL = server->ischannel(data);
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

