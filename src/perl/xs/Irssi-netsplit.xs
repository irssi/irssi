MODULE = Irssi	PACKAGE = Irssi::Server

Irssi::Netsplit
netsplit_find(server, nick, address)
	Irssi::Server server
	char *nick
	char *address

Irssi::Nick
netsplit_find_channel(server, nick, address, channel)
	Irssi::Server server
	char *nick
	char *address
	char *channel


#*******************************
MODULE = Irssi	PACKAGE = Irssi::Netsplit
#*******************************

void
values(netsplit)
	Irssi::Netsplit netsplit
PREINIT:
	HV *hv, *stash;
PPCODE:
	hv = newHV();
	hv_store(hv, "nick", 4, new_pv(netsplit->nick), 0);
	hv_store(hv, "address", 7, new_pv(netsplit->address), 0);
	hv_store(hv, "destroy", 7, newSViv(netsplit->destroy), 0);

	stash = gv_stashpv("Irssi::Netsplitserver", 0);
	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(netsplit->server))), stash), 0);
	/*FIXME: add GSList *channels;*/
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Netsplitserver
#*******************************

void
values(rec)
	Irssi::Netsplitserver rec
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "server", 6, new_pv(rec->server), 0);
	hv_store(hv, "destserver", 10, new_pv(rec->destserver), 0);
	hv_store(hv, "count", 5, newSViv(rec->count), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
