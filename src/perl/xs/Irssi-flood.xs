MODULE = Irssi	PACKAGE = Irssi::Server

void
autoignore_add(server, nick, level)
	Irssi::Server server
	char *nick
	int level

int
autoignore_remove(server, mask, level)
	Irssi::Server server
	char *mask
	int level

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Autoignore
#*******************************

void
values(ai)
	Irssi::Autoignore ai
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "nick", 4, new_pv(ai->nick), 0);
	hv_store(hv, "timeleft", 8, newSViv(ai->timeleft), 0);
	hv_store(hv, "level", 5, newSViv(ai->level), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
