MODULE = Irssi	PACKAGE = Irssi

char *
modes_join(old, mode)
	char *old
	char *mode

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Server
#*******************************

void
channel_set_singlemode(server, channel, nicks, mode)
	Irssi::Server server
	char *channel
	char *nicks
	char *mode

void
channel_set_mode(server, channel, mode)
	Irssi::Server server
	char *channel
	char *mode

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Channel  PREFIX = channel_
#*******************************

void
parse_channel_modes(channel, setby, modestr)
	Irssi::Channel channel
	char *setby
	char *modestr

Irssi::Ban
banlist_add(channel, ban, nick, time)
	Irssi::Channel channel
	char *ban
	char *nick
	time_t time

void
banlist_remove(channel, ban)
	Irssi::Channel channel
	char *ban

Irssi::Ban
banlist_exception_add(channel, ban, nick, time)
	Irssi::Channel channel
	char *ban
	char *nick
	time_t time

void
banlist_exception_remove(channel, ban)
	Irssi::Channel channel
	char *ban

void
invitelist_add(channel, mask)
	Irssi::Channel channel
	char *mask

void
invitelist_remove(channel, mask)
	Irssi::Channel channel
	char *mask
