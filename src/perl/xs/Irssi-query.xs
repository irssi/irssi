MODULE = Irssi  PACKAGE = Irssi

void
queries()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Query", 0);
	for (tmp = queries; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Server
#*******************************

void
queries(server)
	Irssi::Server server
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Query", 0);
	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

Irssi::Query
query_create(server, nick, automatic)
	Irssi::Server server
	char *nick
	int automatic

Irssi::Query
query_find(server, nick)
	Irssi::Server server
	char *nick

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Query  PREFIX = query_
#*******************************

void
values(query)
	Irssi::Query query
PREINIT:
        HV *hv, *stash;
	char *type;
PPCODE:
	type = "query";

	hv = newHV();
	hv_store(hv, "type", 4, new_pv(type), 0);

	stash = gv_stashpv("Irssi::Server", 0);
	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(query->server))), stash), 0);
	hv_store(hv, "nick", 4, new_pv(query->nick), 0);
	hv_store(hv, "new_data", 8, newSViv(query->new_data), 0);

	hv_store(hv, "address", 7, new_pv(query->address), 0);
	hv_store(hv, "server_tag", 10, new_pv(query->server_tag), 0);

	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
query_destroy(query)
	Irssi::Query query

void
query_change_server(query, server)
	Irssi::Query query
	Irssi::Server server
