MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Channel  PREFIX = irc_

void
bans(channel)
	Irssi::Irc::Channel channel
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = channel->banlist; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Irc::Ban")));
	}

void
ebans(channel)
	Irssi::Irc::Channel channel
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = channel->ebanlist; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Irc::Ban")));
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

Irssi::Irc::Nick
irc_nick_insert(channel, nick, op, voice, send_massjoin)
	Irssi::Irc::Channel channel
	char *nick
	int op
	int voice
	int send_massjoin
CODE:
	RETVAL = irc_nicklist_insert(channel, nick, op, voice, send_massjoin);
OUTPUT:
	RETVAL

MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server  PREFIX = irc_

Irssi::Irc::Channel
irc_channel_create(server, name, automatic)
	Irssi::Irc::Server server
	char *name
	int automatic
