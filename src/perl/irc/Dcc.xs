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

void
init(dcc)
	Irssi::Irc::Dcc dcc
PREINIT:
        HV *hv, *stash;
PPCODE:
	hv = newHV();
	hv_store(hv, "type", 4, new_pv((char *) dcc_type2str(dcc->type)), 0);
	hv_store(hv, "created", 7, newSViv(dcc->created), 0);

	hv_store(hv, "server", 6, irssi_bless(dcc->server), 0);
	hv_store(hv, "nick", 4, new_pv(dcc->nick), 0);

	stash = gv_stashpv("Irssi::Irc::Dcc", 0);
	hv_store(hv, "chat", 4, new_bless(dcc->chat, stash), 0);

	hv_store(hv, "ircnet", 6, new_pv(dcc->ircnet), 0);
	hv_store(hv, "mynick", 6, new_pv(dcc->mynick), 0);

	hv_store(hv, "arg", 3, new_pv(dcc->arg), 0);
	hv_store(hv, "file", 4, new_pv(dcc->file), 0);

	hv_store(hv, "addr", 4, new_pv(dcc->addrstr), 0);
	hv_store(hv, "port", 4, newSViv(dcc->port), 0);

	hv_store(hv, "size", 4, newSViv(dcc->size), 0);
	hv_store(hv, "transfd", 7, newSViv(dcc->transfd), 0);
	hv_store(hv, "skipped", 7, newSViv(dcc->skipped), 0);
	hv_store(hv, "starttime", 9, newSViv(dcc->starttime), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

