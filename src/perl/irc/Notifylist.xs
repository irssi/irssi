MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

void
notifies()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Irc::Notifylist", 0);
	for (tmp = notifies; tmp != NULL; tmp = tmp->next) {
		push_bless(tmp->data, stash);
	}

Irssi::Irc::Notifylist
notifylist_add(mask, ircnets, away_check, idle_check_time)
	char *mask
	char *ircnets
	int away_check
	int idle_check_time

void
notifylist_remove(mask)
	char *mask

Irssi::Irc::Server
notifylist_ison(nick, serverlist)
	char *nick
	char *serverlist

Irssi::Irc::Notifylist
notifylist_find(mask, ircnet)
	char *mask
	char *ircnet

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Irc::Server
#*******************************

int
notifylist_ison_server(server, nick)
	Irssi::Irc::Server server
	char *nick

#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Notifylist  PREFIX = notifylist_
#*******************************

void
init(notify)
	Irssi::Irc::Notifylist notify
PREINIT:
	HV *hv;
	AV *av;
	char **tmp;
PPCODE:
	hv = newHV();
	hv_store(hv, "mask", 4, new_pv(notify->mask), 0);
	hv_store(hv, "away_check", 10, newSViv(notify->away_check), 0);
	hv_store(hv, "idle_check_time", 15, newSViv(notify->idle_check_time), 0);

	av = newAV();
	for (tmp = notify->ircnets; *tmp != NULL; tmp++) {
		av_push(av, new_pv(*tmp));
	}
	hv_store(hv, "ircnets", 7, newRV_noinc((SV*)av), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

int
notifylist_ircnets_match(rec, ircnet)
	Irssi::Irc::Notifylist rec
	char *ircnet
