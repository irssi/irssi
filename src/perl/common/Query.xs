MODULE = Irssi  PACKAGE = Irssi

void
queries()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = queries; tmp != NULL; tmp = tmp->next) {
		QUERY_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(irssi_bless(rec)));
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

		XPUSHs(sv_2mortal(irssi_bless(rec)));
	}

Irssi::Query
query_create(chat_type, server_tag, nick, automatic)
	int chat_type
	char *server_tag
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
query_destroy(query)
	Irssi::Query query

void
query_change_server(query, server)
	Irssi::Query query
	Irssi::Server server
