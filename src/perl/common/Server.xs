MODULE = Irssi  PACKAGE = Irssi

void
servers()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))),
					   irssi_get_stash(rec))));
	}

void
reconnects()
PREINIT:
	GSList *tmp;
        HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Reconnect", 0);
	for (tmp = reconnects; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

Irssi::Connect
server_create_conn(dest, port=6667, password=NULL, nick=NULL)
	char *dest
	int port
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
values(server)
	Irssi::Server server
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	perl_server_fill_hash(hv, server);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

Irssi::Server
server_connect(conn)
	Irssi::Connect conn

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

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Connect  PREFIX = server_
#*******************************

void
values(conn)
	Irssi::Connect conn
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	perl_connect_fill_hash(hv, conn);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

Irssi::Server
server_connect(conn)
	Irssi::Connect conn

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Reconnect
#*******************************

void
values(reconnect)
	Irssi::Reconnect reconnect
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	perl_connect_fill_hash(hv, reconnect->conn);
	hv_store(hv, "tag", 3, newSViv(reconnect->tag), 0);
	hv_store(hv, "next_connect", 12, newSViv(reconnect->next_connect), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

