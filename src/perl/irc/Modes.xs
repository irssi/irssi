MODULE = Irssi::Irc	PACKAGE = Irssi::Irc

char *
modes_join(old, mode)
	char *old
	char *mode

#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server
#*******************************

void
channel_set_singlemode(server, channel, nicks, mode)
	Irssi::Irc::Server server
	char *channel
	char *nicks
	char *mode

void
channel_set_mode(server, channel, mode)
	Irssi::Irc::Server server
	char *channel
	char *mode

#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Channel  PREFIX = channel_
#*******************************

void
parse_channel_modes(channel, setby, modestr)
	Irssi::Irc::Channel channel
	char *setby
	char *modestr

Irssi::Irc::Ban
banlist_add(channel, ban, nick, time)
	Irssi::Irc::Channel channel
	char *ban
	char *nick
	time_t time

void
banlist_remove(channel, ban)
	Irssi::Irc::Channel channel
	char *ban

Irssi::Irc::Ban
banlist_exception_add(channel, ban, nick, time)
	Irssi::Irc::Channel channel
	char *ban
	char *nick
	time_t time

void
banlist_exception_remove(channel, ban)
	Irssi::Irc::Channel channel
	char *ban

void
invitelist_add(channel, mask)
	Irssi::Irc::Channel channel
	char *mask

void
invitelist_remove(channel, mask)
	Irssi::Irc::Channel channel
	char *mask
