MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

void
dccs()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Irc::Dcc", 0);
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
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
dcc_ctcp_message(target, server, chat, notice, msg)
	char *target
	Irssi::Irc::Server server
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
values(dcc)
	Irssi::Irc::Dcc dcc
PREINIT:
        HV *hv, *stash;
PPCODE:
	hv = newHV();
	hv_store(hv, "type", 4, new_pv((char *) dcc_type2str(dcc->type)), 0);
	hv_store(hv, "created", 7, newSViv(dcc->created), 0);

	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(dcc->server))),
					   irssi_get_stash(dcc->server)), 0);
	hv_store(hv, "nick", 4, new_pv(dcc->nick), 0);

	stash = gv_stashpv("Irssi::Irc::Dcc", 0);
	hv_store(hv, "chat", 4, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(dcc->chat))), stash), 0);

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

