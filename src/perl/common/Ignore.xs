MODULE = Irssi  PACKAGE = Irssi

void
ignores()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Ignore", 0);
	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

int
ignore_check(nick, host, channel, text, level)
	char *nick
	char *host
	char *channel
	char *text
	int level
CODE:
	RETVAL = ignore_check(NULL, nick, host, channel, text, level);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Server
#*******************************

int
ignore_check(server, nick, host, channel, text, level)
	Irssi::Server server
	char *nick
	char *host
	char *channel
	char *text
	int level

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Ignore  PREFIX = ignore_
#*******************************

void
values(ignore)
	Irssi::Ignore ignore
PREINIT:
        HV *hv;
	AV *av;
	char **tmp;
PPCODE:
	hv = newHV();
	hv_store(hv, "mask", 4, new_pv(ignore->mask), 0);
	hv_store(hv, "servertag", 9, new_pv(ignore->servertag), 0);
	av = newAV();
	for (tmp = ignore->channels; *tmp != NULL; tmp++) {
		av_push(av, new_pv(*tmp));
	}
	hv_store(hv, "channels", 8, newRV_noinc((SV*)av), 0);
	hv_store(hv, "pattern", 7, new_pv(ignore->pattern), 0);

	hv_store(hv, "level", 5, newSViv(ignore->level), 0);
	hv_store(hv, "except_level", 12, newSViv(ignore->except_level), 0);

	hv_store(hv, "regexp", 6, newSViv(ignore->regexp), 0);
	hv_store(hv, "fullword", 8, newSViv(ignore->fullword), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
ignore_add_rec(rec)
	Irssi::Ignore rec

void
ignore_update_rec(rec)
	Irssi::Ignore rec
