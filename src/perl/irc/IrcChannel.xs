MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Channel  PREFIX = irc_channel_

void
bans(channel)
	Irssi::Irc::Channel channel
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Irc::Ban", 0);
	for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
		push_bless(tmp->data, stash);
	}

void
ebans(channel)
	Irssi::Irc::Channel channel
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Irc::Ban", 0);
	for (tmp = channel->ebanlist; tmp != NULL; tmp = tmp->next) {
		push_bless(tmp->data, stash);
	}

void
invites(channel)
	Irssi::Irc::Channel channel
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = channel->invitelist; tmp != NULL; tmp = tmp->next) {
		XPUSHs(new_pv(tmp->data));
	}

MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server  PREFIX = irc_

Irssi::Irc::Channel
irc_channel_create(server, name, automatic)
	Irssi::Irc::Server server
	char *name
	int automatic
