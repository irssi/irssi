MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

void
ban_set_type(type)
	char *type

#*******************************
MODULE = Irssi::Irc  PACKAGE = Irssi::Irc::Channel
#*******************************

char *
ban_get_mask(channel, nick)
	Irssi::Irc::Channel channel
	char *nick

void
ban_set(channel, bans)
	Irssi::Irc::Channel channel
	char *bans

void
ban_remove(channel, ban)
	Irssi::Irc::Channel channel
	char *ban

#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Ban
#*******************************

void
values(ban)
	Irssi::Irc::Ban ban
PREINIT:
	HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "ban", 3, new_pv(ban->ban), 0);
	hv_store(hv, "setby", 5, new_pv(ban->setby), 0);
	hv_store(hv, "time", 4, newSViv(ban->time), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
