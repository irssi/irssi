MODULE = Irssi  PACKAGE = Irssi

void
queries()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))),
					   irssi_get_stash(rec))));
	}

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Server
#*******************************

void
queries(server)
	Irssi::Server server
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = server->queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))),
					   irssi_get_stash(rec))));
	}

Irssi::Query
query_create(chat_type, server, nick, automatic)
	int chat_type
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
        HV *hv;
PPCODE:
	hv = newHV();
        perl_query_fill_hash(hv, query);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
query_destroy(query)
	Irssi::Query query

void
query_change_server(query, server)
	Irssi::Query query
	Irssi::Server server
