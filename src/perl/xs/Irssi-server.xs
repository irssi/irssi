MODULE = Irssi  PACKAGE = Irssi

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
irc_server_create_conn(dest, port=6667, password=NULL, nick=NULL)
	char *dest
	int port
	char *password
	char *nick

Irssi::Server
server_find_tag(tag)
	char *tag
CODE:
	RETVAL = (IRC_SERVER_REC *) server_find_tag(tag);
OUTPUT:
	RETVAL

Irssi::Server
server_find_ircnet(ircnet)
	char *ircnet
CODE:
	RETVAL = (IRC_SERVER_REC *) server_find_ircnet(ircnet);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Server  PREFIX = server_
#*******************************

void
values(server)
	Irssi::Server server
PREINIT:
        HV *hv;
	char *type;
PPCODE:
	type = "IRC";

	hv = newHV();
	hv_store(hv, "type", 4, new_pv(type), 0);
	server_fill_hash(hv, server);

	hv_store(hv, "real_address", 12, new_pv(server->real_address), 0);
	hv_store(hv, "version", 7, new_pv(server->version), 0);
	hv_store(hv, "usermode", 8, new_pv(server->usermode), 0);
	hv_store(hv, "userhost", 8, new_pv(server->userhost), 0);
	hv_store(hv, "last_invite", 11, new_pv(server->last_invite), 0);
	hv_store(hv, "away_reason", 11, new_pv(server->away_reason), 0);
	hv_store(hv, "usermode_away", 13, newSViv(server->usermode_away), 0);
	hv_store(hv, "server_operator", 15, newSViv(server->server_operator), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

int
server_connect(server)
	Irssi::Server server
CODE:
	RETVAL = server_connect((SERVER_REC *) server);
OUTPUT:
	RETVAL

void
server_disconnect(server)
	Irssi::Server server
CODE:
	server_disconnect((SERVER_REC *) server);

char *
irc_server_get_channels(server)
	Irssi::Server server

void
send_raw(server, cmd)
	Irssi::Server server
	char *cmd
CODE:
	irc_send_cmd(server, cmd);

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

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Connect  PREFIX = irc_server_
#*******************************

void
values(conn)
	Irssi::Connect conn
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	connect_fill_hash(hv, conn);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

Irssi::Server
irc_server_connect(conn)
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
	add_connect_hash(hv, reconnect->conn);
	hv_store(hv, "tag", 3, newSViv(reconnect->tag), 0);
	hv_store(hv, "next_connect", 12, newSViv(reconnect->next_connect), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

