MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server

Irssi::Irc::Netsplit
netsplit_find(server, nick, address)
	Irssi::Irc::Server server
	char *nick
	char *address

Irssi::Irc::Nick
netsplit_find_channel(server, nick, address, channel)
	Irssi::Irc::Server server
	char *nick
	char *address
	char *channel


#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Netsplit
#*******************************

void
init(netsplit)
	Irssi::Irc::Netsplit netsplit
PREINIT:
	HV *hv, *stash;
PPCODE:
	hv = newHV();
	hv_store(hv, "nick", 4, new_pv(netsplit->nick), 0);
	hv_store(hv, "address", 7, new_pv(netsplit->address), 0);
	hv_store(hv, "destroy", 7, newSViv(netsplit->destroy), 0);

	stash = gv_stashpv("Irssi::Irc::Netsplitserver", 0);
	hv_store(hv, "server", 6, new_bless(netsplit->server, stash), 0);
	/*FIXME: add GSList *channels;*/
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Netsplitserver
#*******************************

void
init(rec)
	Irssi::Irc::Netsplitserver rec
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "server", 6, new_pv(rec->server), 0);
	hv_store(hv, "destserver", 10, new_pv(rec->destserver), 0);
	hv_store(hv, "count", 5, newSViv(rec->count), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
