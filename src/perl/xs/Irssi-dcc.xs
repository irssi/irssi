MODULE = Irssi  PACKAGE = Irssi

void
dccs()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Dcc", 0);
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

Irssi::Dcc
dcc_find_item(type, nick, arg)
	int type
	char *nick
	char *arg

Irssi::Dcc
dcc_find_by_port(nick, port)
	char *nick
	int port

char *
dcc_type2str(type)
	int type

int
dcc_str2type(type)
	char *type

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Dcc  PREFIX = dcc_
#*******************************

void
dcc_destroy(dcc)
	Irssi::Dcc dcc
