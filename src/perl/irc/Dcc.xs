MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

void
dccs()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Irc::Dcc", 0);
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		push_bless(tmp->data, stash);
	}

Irssi::Irc::Dcc
dcc_find_item(type, nick, arg)
	int type
	char *nick
	char *arg

Irssi::Irc::Dcc
dcc_find_by_port(nick, port)
	char *nick
	int port

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Windowitem PREFIX = item_
#*******************************

Irssi::Irc::Dcc
item_get_dcc(item)
	Irssi::Windowitem item

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Irc::Server
#*******************************

void
dcc_ctcp_message(server, target, notice, msg)
	Irssi::Irc::Server server
	char *target
	int notice
	char *msg
CODE:
	dcc_ctcp_message(server, target, NULL, notice, msg);

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Irc::Dcc  PREFIX = dcc_
#*******************************

void
dcc_ctcp_message(chat, target, notice, msg)
	Irssi::Irc::Dcc chat
	char *target
	int notice
	char *msg
CODE:
	dcc_ctcp_message(chat->server, target, chat, notice, msg);

void
dcc_destroy(dcc)
	Irssi::Irc::Dcc dcc

void
dcc_chat_send(dcc, data)
	Irssi::Irc::Dcc dcc
	char *data
