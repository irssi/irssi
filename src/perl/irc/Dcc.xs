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
dcc_find_request_latest(type)
	int type

Irssi::Irc::Dcc
dcc_find_request(type, nick, arg)
	int type
	char *nick
	char *arg

char *
dcc_get_download_path(fname)
	char *fname

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Irc::Dcc  PREFIX = dcc_
#*******************************

void
dcc_destroy(dcc)
	Irssi::Irc::Dcc dcc

void 
dcc_reject(dcc, server)
	Irssi::Irc::Dcc dcc
	Irssi::Irc::Server server
