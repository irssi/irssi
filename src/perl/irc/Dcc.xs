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

void
dcc_ctcp_message(server, target, chat, notice, msg)
	Irssi::Irc::Server server
	char *target
	Irssi::Irc::Dcc chat
	int notice
	char *msg

Irssi::Irc::Dcc
item_get_dcc(item)
	void *item

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Irc::Dcc  PREFIX = dcc_
#*******************************

void
dcc_destroy(dcc)
	Irssi::Irc::Dcc dcc

void
dcc_chat_send(dcc, data)
	Irssi::Irc::Dcc dcc
	char *data
