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
